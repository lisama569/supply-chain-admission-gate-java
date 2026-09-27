package com.github.lisama569.supplychainadmissiongatejava.importing;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.Permission;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import com.github.lisama569.supplychainadmissiongatejava.importing.SourceConsistencyVerifier;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.NormalizedManifest;
import com.github.lisama569.supplychainadmissiongatejava.model.Provenance;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.parse.ManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.parse.ManifestParserRegistry;
import com.github.lisama569.supplychainadmissiongatejava.parse.ProvenanceParser;
import com.github.lisama569.supplychainadmissiongatejava.persist.ArtifactRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.IdempotencyRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.PolicyRepository;
import com.github.lisama569.supplychainadmissiongatejava.rbac.AccessControl;
import com.github.lisama569.supplychainadmissiongatejava.security.HmacSigner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * 材料导入与归一化服务。
 *
 * <p>固定处理顺序：鉴权 → 请求体哈希/幂等检查 → HMAC 验签 → JSON 解析 → 格式版本校验
 * → 归一化 →（来源材料时）一致性校验 → 原子落库。任何一步失败都给出可区分的拒绝原因，
 * 绝不静默通过。</p>
 */
@Service
public class ImportService {

    private final ManifestParserRegistry parserRegistry;
    private final ProvenanceParser provenanceParser;
    private final ArtifactRepository artifactRepository;
    private final IdempotencyRepository idempotencyRepository;
    private final PolicyRepository policyRepository;
    private final AccessControl accessControl;
    private final HmacSigner signer;

    public ImportService(ManifestParserRegistry parserRegistry,
                         ProvenanceParser provenanceParser,
                         ArtifactRepository artifactRepository,
                         IdempotencyRepository idempotencyRepository,
                         PolicyRepository policyRepository,
                         AccessControl accessControl,
                         HmacSigner signer) {
        this.parserRegistry = parserRegistry;
        this.provenanceParser = provenanceParser;
        this.artifactRepository = artifactRepository;
        this.idempotencyRepository = idempotencyRepository;
        this.policyRepository = policyRepository;
        this.accessControl = accessControl;
        this.signer = signer;
    }

    /**
     * 导入已签名清单。
     *
     @param requestId     幂等键；同键重复请求返回首次结果，请求体不同则拒绝
     * @param format        spdx / cyclonedx / internal
     * @param manifestBytes 清单原始字节
     * @param signatureHex  清单字节的 HMAC-SHA256 十六进制
     */
    public synchronized ArtifactRecord importManifest(UserContext user,
                                                      String requestId,
                                                      String format,
                                                      byte[] manifestBytes,
                                                      String signatureHex) {
        accessControl.require(user, Permission.IMPORT_MATERIAL);
        requireRequestId(requestId);
        if (manifestBytes == null || manifestBytes.length == 0) {
            throw new GateException(RejectionReason.MISSING_FIELD, "清单内容为空");
        }
        String payloadHash = sha256Hex(concat(format.getBytes(StandardCharsets.UTF_8), manifestBytes));
        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(requestId);
        if (existing.isPresent()) {
            return reuseOrReject(existing.get(), payloadHash, "artifact:");
        }

        verifySignature(manifestBytes, signatureHex);

        JsonNode root = readJson(manifestBytes);
        ManifestParser parser = parserRegistry.require(format);
        NormalizedManifest manifest = parser.parse(root);

        String artifactKey = artifactKey(manifest);
        ArtifactRecord record = new ArtifactRecord(artifactKey,
                manifest.artifactName(), manifest.artifactVersion(), manifest.artifactDigest(),
                manifest, null, null, Instant.now(), user.username(), requestId);

        ArtifactRecord saved = artifactRepository.save(record);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                requestId, payloadHash, "artifact:" + artifactKey, Instant.now()));
        return saved;
    }

    /** 为已导入制品补充已签名来源材料，并执行来源一致性校验。 */
    public synchronized ArtifactRecord attachProvenance(UserContext user,
                                                        String requestId,
                                                        String artifactKey,
                                                        byte[] provenanceBytes,
                                                        String signatureHex) {
        accessControl.require(user, Permission.IMPORT_MATERIAL);
        requireRequestId(requestId);
        if (provenanceBytes == null || provenanceBytes.length == 0) {
            throw new GateException(RejectionReason.MISSING_FIELD, "来源材料内容为空");
        }
        String payloadHash = sha256Hex(
                concat(artifactKey.getBytes(StandardCharsets.UTF_8), provenanceBytes));
        Optional<IdempotencyRepository.Entry> existing = idempotencyRepository.find(requestId);
        if (existing.isPresent()) {
            return reuseOrReject(existing.get(), payloadHash, "artifact:");
        }

        ArtifactRecord artifact = artifactRepository.find(artifactKey)
                .orElseThrow(() -> new GateException(RejectionReason.NOT_FOUND,
                        "制品不存在，无法附加来源材料: " + artifactKey));

        verifySignature(provenanceBytes, signatureHex);

        JsonNode root = readJson(provenanceBytes);
        Provenance provenance = provenanceParser.parse(root);

        if (!provenance.digestHex().equalsIgnoreCase(artifact.digestHex())) {
            throw new GateException(RejectionReason.PROVENANCE_MISMATCH,
                    "来源摘要与已导入制品摘要不一致：provenance=" + provenance.digestHex()
                            + "，artifact=" + artifact.digestHex());
        }
        Policy snapshot = policyRepository.current();
        SourceConsistencyVerifier.verify(artifact.manifest(), provenance,
                snapshot.trustedBuilders());

        ArtifactRecord updated = new ArtifactRecord(artifact.artifactKey(), artifact.name(),
                artifact.version(), artifact.digestHex(), artifact.manifest(), provenance,
                "signed-provenance", artifact.importedAt(), artifact.importedBy(),
                artifact.importRequestId());
        ArtifactRecord saved = artifactRepository.save(updated);
        idempotencyRepository.saveIfAbsent(new IdempotencyRepository.Entry(
                requestId, payloadHash, "artifact:" + artifact.artifactKey(), Instant.now()));
        return saved;
    }

    private void verifySignature(byte[] payload, String signatureHex) {
        if (signatureHex == null || signatureHex.isBlank()) {
            throw new GateException(RejectionReason.MISSING_SIGNATURE, "材料缺少签名");
        }
        if (!signer.verifyHex(payload, signatureHex)) {
            throw new GateException(RejectionReason.INVALID_SIGNATURE,
                    "签名验签失败（HMAC-SHA256）");
        }
    }

    private ArtifactRecord reuseOrReject(IdempotencyRepository.Entry entry,
                                         String payloadHash, String refPrefix) {
        if (!entry.requestHash().equals(payloadHash)) {
            throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                    "幂等键 " + entry.requestId() + " 已用于不同的请求体");
        }
        String ref = entry.resultRef();
        if (ref != null && ref.startsWith(refPrefix)) {
            String key = ref.substring(refPrefix.length());
            return artifactRepository.find(key)
                    .orElseThrow(() -> new GateException(RejectionReason.ILLEGAL_STATE,
                            "幂等结果引用的制品已丢失: " + key));
        }
        throw new GateException(RejectionReason.DUPLICATE_CONFLICT,
                "幂等键 " + entry.requestId() + " 的结果类型不匹配");
    }

    private static void requireRequestId(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少幂等键 requestId");
        }
    }

    private static String artifactKey(NormalizedManifest manifest) {
        return manifest.artifactName() + "@" + manifest.artifactVersion();
    }

    private static JsonNode readJson(byte[] bytes) {
        try {
            JsonNode node = new com.fasterxml.jackson.databind.ObjectMapper().readTree(bytes);
            if (node == null || !node.isObject()) {
                throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "JSON 根节点必须为对象");
            }
            return node;
        } catch (IOException e) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "材料不是合法 JSON: " + e.getMessage(), e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HmacSigner.encodeHex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
