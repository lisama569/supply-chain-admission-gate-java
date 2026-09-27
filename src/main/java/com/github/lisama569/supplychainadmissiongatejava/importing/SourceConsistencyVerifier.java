package com.github.lisama569.supplychainadmissiongatejava.importing;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.NormalizedManifest;
import com.github.lisama569.supplychainadmissiongatejava.model.Provenance;
import java.util.List;

/**
 * 来源一致性校验：清单与来源材料之间的信息矛盾必须显式拒绝。
 * 本地模拟覆盖两类矛盾：
 * 1. 来源材料声明的 subject 摘要/算法与清单不一致（{@link RejectionReason#PROVENANCE_MISMATCH}）；
 * 2. 来源构建者既不在可信构建者列表、又与清单 supplier 归属不一致
 * （{@link RejectionReason#INCONSISTENT_SOURCE}）。
 *
 * <p>可信构建者代表经过验证的构建通道（可跨组织代构建），因此豁免 supplier 归属比对；
 * 非可信构建者必须与声明供应商归属一致，防止“同摘要、来源掉包”静默通过。</p>
 */
public final class SourceConsistencyVerifier {

    private SourceConsistencyVerifier() {
    }

    public static void verify(NormalizedManifest manifest, Provenance provenance) {
        verify(manifest, provenance, List.of());
    }

    public static void verify(NormalizedManifest manifest,
                              Provenance provenance,
                              List<String> trustedBuilders) {
        if (manifest == null) {
            throw new GateException(RejectionReason.MISSING_FIELD, "清单为空，无法校验来源一致性");
        }
        if (provenance == null) {
            throw new GateException(RejectionReason.MISSING_PROVENANCE,
                    "制品 " + manifest.artifactName() + "@" + manifest.artifactVersion()
                            + " 缺少来源材料");
        }

        if (!provenance.digestAlg().equalsIgnoreCase(manifest.digestAlg())) {
            throw new GateException(RejectionReason.PROVENANCE_MISMATCH,
                    "摘要算法不一致：provenance=" + provenance.digestAlg()
                            + "，manifest=" + manifest.digestAlg());
        }
        if (!provenance.digestHex().equalsIgnoreCase(manifest.artifactDigest())) {
            throw new GateException(RejectionReason.PROVENANCE_MISMATCH,
                    "来源摘要与清单摘要不一致：provenance=" + provenance.digestHex()
                            + "，manifest=" + manifest.artifactDigest());
        }

        boolean trusted = trustedBuilders.stream()
                .anyMatch(t -> t.equalsIgnoreCase(provenance.builderId()));
        if (trusted) {
            return;
        }
        String supplier = manifest.supplier();
        if (supplier != null && !supplier.isBlank()
                && !organizationsAgree(supplier, provenance.builderId())) {
            throw new GateException(RejectionReason.INCONSISTENT_SOURCE,
                    "来源信息矛盾：清单 supplier=" + supplier
                            + " 与非可信来源 builderId=" + provenance.builderId() + " 归属不一致");
        }
    }

    /**
     * 确定性的本地归属规则（仅用于样本）：把 purl/URL 形式的标识规范化、去掉版本后缀后，
     * 按 {@code / : @ .} 分段；任一非平凡（长度≥3）分段相等或互相包含即判定归属一致。
     * 信息不足（任一侧抽不出标识）时不臆断，判为一致。
     */
    static boolean organizationsAgree(String supplier, String builderId) {
        String s = stripVersion(normalize(supplier));
        String b = stripVersion(normalize(builderId));
        if (s.isEmpty() || b.isEmpty()) {
            return true;
        }
        if (s.equals(b) || s.contains(b) || b.contains(s)) {
            return true;
        }
        for (String part : b.split("[/:.@]+")) {
            if (part.length() >= 3 && (part.equals(s) || part.contains(s) || s.contains(part))) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String raw) {
        return raw.trim().toLowerCase()
                .replaceFirst("^organization:\\s*", "")
                .replaceFirst("^person:\\s*", "")
                .replaceFirst("^pkg:", "")
                .replaceFirst("^git\\+", "")
                .replaceFirst("^https?://", "");
    }

    private static String stripVersion(String normalized) {
        int at = normalized.indexOf('@');
        return at >= 0 ? normalized.substring(0, at) : normalized;
    }
}
