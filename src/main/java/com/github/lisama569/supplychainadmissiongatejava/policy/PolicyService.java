package com.github.lisama569.supplychainadmissiongatejava.policy;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.Permission;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.persist.IdempotencyRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.PolicyRepository;
import com.github.lisama569.supplychainadmissiongatejava.rbac.AccessControl;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/** 策略发布与查询：角色限制 + 乐观锁版本控制 + 幂等发布。 */
@Service
public class PolicyService {

    private final PolicyRepository policyRepository;
    private final IdempotencyRepository idempotencyRepository;
    private final AccessControl accessControl;

    public PolicyService(PolicyRepository policyRepository,
                         IdempotencyRepository idempotencyRepository,
                         AccessControl accessControl) {
        this.policyRepository = policyRepository;
        this.idempotencyRepository = idempotencyRepository;
        this.accessControl = accessControl;
    }

    /** 待发布的策略内容（不含版本号，版本号由仓储分配）。 */
    public record Draft(Severity blockSeverity,
                        List<String> blockedLicenses,
                        boolean blockCopyleft,
                        int requiredSlsaLevel,
                        boolean requireVerifiedBuilder,
                        List<String> trustedBuilders,
                        String note) {
    }

    public Policy current() {
        return policyRepository.current();
    }

    /**
     * 发布新策略版本。
     *
     * @param expectedVersion 调用方看到的当前版本；不匹配则 POLICY_VERSION_CONFLICT
     * @param requestId       幂等键；重复发布同一请求返回同一版本；同键不同体则 DUPLICATE_CONFLICT
     */
    public synchronized Policy publish(UserContext user,
                                       String requestId,
                                       long expectedVersion,
                                       Draft draft) {
        accessControl.require(user, Permission.PUBLISH_POLICY);
        if (requestId == null || requestId.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少幂等键 requestId");
        }
        validate(draft, expectedVersion);

        String payloadHash = ImportHash.draftHash(expectedVersion, draft);
        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(requestId);
        if (existing.isPresent()) {
            return reuseOrReject(existing.get(), payloadHash);
        }

        // 不在锁外预读 current；基线校验与版本分配必须在仓储同一临界区内原子完成，
        // 否则两个并发请求会读到同一旧版本而双双提交（丢失更新）。
        Policy next = new Policy(expectedVersion + 1,
                draft.blockSeverity(), draft.blockedLicenses(), draft.blockCopyleft(),
                draft.requiredSlsaLevel(), draft.requireVerifiedBuilder(), draft.trustedBuilders(),
                Instant.now().toEpochMilli(), user.username(), draft.note());

        Policy published = policyRepository.publishIfCurrent(expectedVersion, next);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                requestId, payloadHash, "policy:v" + published.version(), Instant.now()));
        return published;
    }

    public Policy getVersion(long version) {
        return policyRepository.findVersion(version)
                .orElseThrow(() -> new GateException(RejectionReason.POLICY_NOT_FOUND,
                        "策略版本不存在: v" + version));
    }

    public List<Policy> history() {
        return policyRepository.history();
    }

    private Policy reuseOrReject(IdempotencyRepository.Entry entry, String payloadHash) {
        if (!entry.requestHash().equals(payloadHash)) {
            throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                    "幂等键 " + entry.requestId() + " 已用于不同的发布请求");
        }
        String ref = entry.resultRef();
        if (ref != null && ref.startsWith("policy:v")) {
            long version = Long.parseLong(ref.substring("policy:v".length()));
            return getVersion(version);
        }
        throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                "幂等键 " + entry.requestId() + " 的结果类型不匹配");
    }

    private static void validate(Draft draft, long expectedVersion) {
        if (draft == null) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少策略内容");
        }
        if (expectedVersion < 0) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "expectedVersion 不能为负数");
        }
        if (draft.blockSeverity() == null) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少 blockSeverity");
        }
        if (draft.requiredSlsaLevel() < 0 || draft.requiredSlsaLevel() > 4) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "requiredSlsaLevel 必须在 0-4 之间");
        }
        if (draft.blockedLicenses() == null || draft.trustedBuilders() == null) {
            throw new GateException(RejectionReason.MISSING_FIELD,
                    "blockedLicenses 与 trustedBuilders 必须提供（可为空数组）");
        }
    }

    private static final class ImportHash {
        static String draftHash(long expectedVersion, Draft draft) {
            String raw = expectedVersion + "|"
                    + draft.blockSeverity() + "|"
                    + draft.blockedLicenses() + "|"
                    + draft.blockCopyleft() + "|"
                    + draft.requiredSlsaLevel() + "|"
                    + draft.requireVerifiedBuilder() + "|"
                    + draft.trustedBuilders() + "|"
                    + draft.note();
            return com.github.lisama569.supplychainadmissiongatejava.importing.ImportService
                    .sha256Hex(raw.getBytes(StandardCharsets.UTF_8));
        }
    }
}
