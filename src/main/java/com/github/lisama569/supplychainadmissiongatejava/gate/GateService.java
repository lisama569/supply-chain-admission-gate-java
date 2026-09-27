package com.github.lisama569.supplychainadmissiongatejava.gate;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.Permission;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import com.github.lisama569.supplychainadmissiongatejava.decision.DecisionEngine;
import com.github.lisama569.supplychainadmissiongatejava.importing.ImportService;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionFinding;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.RiskType;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.persist.ArtifactRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.DecisionRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.IdempotencyRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.PolicyRepository;
import com.github.lisama569.supplychainadmissiongatejava.rbac.AccessControl;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * 准入门面：自动判定、人工隔离、安全覆盖与历史查询。
 *
 * <p>判定开始时一次性读取“制品快照 + 当前策略快照”，整个评估只读这两个快照，
 * 因此即使期间发生策略切换或并发导入，也不会出现半更新/混合版本结果。</p>
 */
@Service
public class GateService {

    private final ArtifactRepository artifactRepository;
    private final DecisionRepository decisionRepository;
    private final PolicyRepository policyRepository;
    private final IdempotencyRepository idempotencyRepository;
    private final DecisionEngine decisionEngine;
    private final AccessControl accessControl;

    public GateService(ArtifactRepository artifactRepository,
                       DecisionRepository decisionRepository,
                       PolicyRepository policyRepository,
                       IdempotencyRepository idempotencyRepository,
                       DecisionEngine decisionEngine,
                       AccessControl accessControl) {
        this.artifactRepository = artifactRepository;
        this.decisionRepository = decisionRepository;
        this.policyRepository = policyRepository;
        this.idempotencyRepository = idempotencyRepository;
        this.decisionEngine = decisionEngine;
        this.accessControl = accessControl;
    }

    /** 自动判定（需准入权限）。同一幂等键重复提交返回首次判定。 */
    public synchronized DecisionRecord decide(UserContext user,
                                              String requestId,
                                              String artifactKey) {
        accessControl.require(user, Permission.ADMIT_ARTIFACT);
        requireRequestId(requestId);
        String idemKey = "decide:" + requestId;

        ArtifactRecord artifact = requireArtifact(artifactKey);
        Policy policy = policyRepository.current(); // 快照只读
        String payloadHash = hash("decide", artifactKey, artifact.digestHex(),
                String.valueOf(policy.version()));

        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(idemKey);
        if (existing.isPresent()) {
            return reuseDecision(existing.get(), payloadHash);
        }

        DecisionEngine.Evaluation evaluation = decisionEngine.evaluate(artifact, policy);
        String decisionId = "dec-" + requestId;
        DecisionRecord record = new DecisionRecord(decisionId, artifactKey, artifact.digestHex(),
                evaluation.status(), policy.version(), evaluation.findings(), evaluation.rationale(),
                Instant.now().toEpochMilli(), user.username(), null, null);
        decisionRepository.save(record);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                idemKey, payloadHash, "decision:" + decisionId, Instant.now()));
        return record;
    }

    /** 人工隔离（需隔离权限）。无论自动判定如何，记录人工结论与原因。 */
    public synchronized DecisionRecord quarantine(UserContext user,
                                                  String requestId,
                                                  String artifactKey,
                                                  String reason) {
        accessControl.require(user, Permission.QUARANTINE_ARTIFACT);
        requireRequestId(requestId);
        if (reason == null || reason.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "人工隔离必须给出原因");
        }
        String idemKey = "quarantine:" + requestId;
        ArtifactRecord artifact = requireArtifact(artifactKey);
        Policy policy = policyRepository.current();
        String payloadHash = hash("quarantine", artifactKey, artifact.digestHex(), reason);

        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(idemKey);
        if (existing.isPresent()) {
            return reuseDecision(existing.get(), payloadHash);
        }

        String decisionId = "qtn-" + requestId;
        List<DecisionFinding> findings = List.of(new DecisionFinding(RiskType.PROVENANCE,
                Severity.HIGH, "MANUAL-QUARANTINE",
                "人工隔离（操作者 " + user.username() + "）：" + reason));
        String rationale = "人工隔离决定，优先于自动判定；原因：" + reason;
        DecisionRecord record = new DecisionRecord(decisionId, artifactKey, artifact.digestHex(),
                DecisionStatus.QUARANTINED, policy.version(), findings, rationale,
                Instant.now().toEpochMilli(), user.username(), null, null);
        decisionRepository.save(record);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                idemKey, payloadHash, "decision:" + decisionId, Instant.now()));
        return record;
    }

    /**
     * 安全覆盖（仅安全官员）：对制品最新结论覆盖为目标状态，必须给出原因。
     * 被覆盖的风险依据原样保留在新记录中，保证可追溯。
     */
    public synchronized DecisionRecord override(UserContext user,
                                                String requestId,
                                                String artifactKey,
                                                DecisionStatus targetStatus,
                                                String reason) {
        accessControl.require(user, Permission.OVERRIDE_DECISION);
        requireRequestId(requestId);
        if (targetStatus != DecisionStatus.ADMITTED && targetStatus != DecisionStatus.QUARANTINED) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "覆盖目标状态只能是 ADMITTED 或 QUARANTINED，实际: " + targetStatus);
        }
        if (reason == null || reason.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "安全覆盖必须给出原因");
        }
        String idemKey = "override:" + requestId;
        ArtifactRecord artifact = requireArtifact(artifactKey);
        Policy policy = policyRepository.current();
        String payloadHash = hash("override", artifactKey, artifact.digestHex(),
                targetStatus.name(), reason);

        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(idemKey);
        if (existing.isPresent()) {
            return reuseDecision(existing.get(), payloadHash);
        }

        DecisionRecord latest = decisionRepository.latestForArtifact(artifactKey).orElse(null);
        List<DecisionFinding> findings = new ArrayList<>();
        if (latest != null) {
            findings.addAll(latest.findings());
        }
        findings.add(new DecisionFinding(RiskType.PROVENANCE, Severity.HIGH, "MANUAL-OVERRIDE",
                "安全官员 " + user.username() + " 覆盖为 " + targetStatus + "，原因：" + reason));
        String rationale = "安全覆盖（仅 SECURITY_OFFICER）：目标状态=" + targetStatus
                + "；原命中风险已保留。覆盖原因：" + reason
                + (latest == null ? "；该制品此前无判定记录。"
                : "；被覆盖判定 " + latest.decisionId() + "（策略 v" + latest.policyVersion() + "）。");

        String decisionId = "ovr-" + requestId;
        DecisionRecord record = new DecisionRecord(decisionId, artifactKey, artifact.digestHex(),
                targetStatus, policy.version(), findings, rationale,
                Instant.now().toEpochMilli(),
                latest == null ? user.username() : latest.decidedBy(),
                user.username(), reason);
        decisionRepository.save(record);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                idemKey, payloadHash, "decision:" + decisionId, Instant.now()));
        return record;
    }

    public synchronized DecisionRecord getDecision(String decisionId) {
        if (decisionId == null || decisionId.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少 decisionId");
        }
        return decisionRepository.find(decisionId)
                .orElseThrow(() -> new GateException(RejectionReason.NOT_FOUND,
                        "判定记录不存在: " + decisionId));
    }

    public synchronized List<DecisionRecord> history(String artifactKey) {
        requireArtifact(artifactKey);
        return decisionRepository.findByArtifact(artifactKey);
    }

    private ArtifactRecord requireArtifact(String artifactKey) {
        if (artifactKey == null || artifactKey.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少 artifactKey");
        }
        return artifactRepository.find(artifactKey)
                .orElseThrow(() -> new GateException(RejectionReason.NOT_FOUND,
                        "制品不存在: " + artifactKey));
    }

    private DecisionRecord reuseDecision(IdempotencyRepository.Entry entry, String payloadHash) {
        if (!entry.requestHash().equals(payloadHash)) {
            throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                    "幂等键 " + entry.requestId() + " 已用于不同的请求");
        }
        String ref = entry.resultRef();
        if (ref != null && ref.startsWith("decision:")) {
            return getDecision(ref.substring("decision:".length()));
        }
        throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                "幂等键 " + entry.requestId() + " 的结果类型不匹配");
    }

    private static void requireRequestId(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少幂等键 requestId");
        }
    }

    private static String hash(String op, String artifactKey, String digest, String... extras) {
        StringBuilder raw = new StringBuilder(op).append('|').append(artifactKey)
                .append('|').append(digest);
        for (String extra : extras) {
            raw.append('|').append(extra);
        }
        return ImportService.sha256Hex(raw.toString().getBytes(StandardCharsets.UTF_8));
    }
}
