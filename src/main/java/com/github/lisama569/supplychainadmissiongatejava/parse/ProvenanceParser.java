package com.github.lisama569.supplychainadmissiongatejava.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Provenance;

/**
 * SLSA 风格 provenance-v1 解析器：
 * <pre>
 * {
 *   "provenanceVersion": 1,
 *   "subject": {"digestAlg": "SHA-256", "digest": "..."},
 *   "builder": {"id": "pkg:generic/trusted-builder@v1"},
 *   "buildType": "...",
 *   "slsaLevel": 3,
 *   "source": {"uri": "git+https://...", "revision": "sha1:..."}
 * }
 * </pre>
 */
@org.springframework.stereotype.Component
public class ProvenanceParser {

    private static final int VERSION = 1;

    public Provenance parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "来源材料根节点必须为对象");
        }
        int version = JsonFields.requireInt(root, "provenanceVersion");
        if (version != VERSION) {
            throw new GateException(RejectionReason.INCOMPATIBLE_VERSION,
                    "不兼容的来源材料版本 provenanceVersion=" + version + "，仅支持 1");
        }
        JsonNode subject = JsonFields.requireObject(root, "subject");
        String alg = JsonFields.requireText(subject, "digestAlg");
        if (!"SHA-256".equalsIgnoreCase(alg)) {
            throw new GateException(RejectionReason.UNSUPPORTED_ALGORITHM,
                    "不支持的摘要算法: " + alg + "，仅支持 SHA-256");
        }
        String digest = JsonFields.requireText(subject, "digest").trim().toLowerCase();
        if (!digest.matches("[0-9a-f]{64}")) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "来源材料中的 SHA-256 摘要格式非法");
        }
        JsonNode builder = JsonFields.requireObject(root, "builder");
        String builderId = JsonFields.requireText(builder, "id");
        int slsaLevel = JsonFields.requireInt(root, "slsaLevel");
        if (slsaLevel < 0 || slsaLevel > 4) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "slsaLevel 必须在 0-4 之间，实际: " + slsaLevel);
        }
        JsonNode source = JsonFields.requireObject(root, "source");
        String uri = JsonFields.requireText(source, "uri");
        String revision = JsonFields.requireText(source, "revision");
        return new Provenance(builderId, uri, revision, slsaLevel, "SHA-256", digest);
    }
}
