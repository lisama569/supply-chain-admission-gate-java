package com.github.lisama569.supplychainadmissiongatejava.decision;

import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.Component;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionFinding;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.License;
import com.github.lisama569.supplychainadmissiongatejava.model.NormalizedManifest;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.Provenance;
import com.github.lisama569.supplychainadmissiongatejava.model.RiskType;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.model.Vulnerability;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 确定性判定引擎。
 *
 * <p>三个风险维度——漏洞、许可、来源——独立评估、全部保留为依据；
 * 当多个维度同时命中时，按固定优先级 {@code VULNERABILITY > LICENSE > PROVENANCE}
 * 决定最终结论，因此同样输入 + 同一策略版本永远得到同样结果（可复现、可解释）。</p>
 */
@org.springframework.stereotype.Component
public class DecisionEngine {

    /** 判定结果（状态 + 全部依据 + 确定性解释）。 */
    public record Evaluation(DecisionStatus status, List<DecisionFinding> findings, String rationale) {
        public Evaluation {
            findings = findings == null ? List.of() : List.copyOf(findings);
        }
    }

    public Evaluation evaluate(ArtifactRecord artifact, Policy policy) {
        List<DecisionFinding> findings = new ArrayList<>();
        findings.addAll(evaluateVulnerabilities(artifact, policy));
        findings.addAll(evaluateLicenses(artifact, policy));
        findings.addAll(evaluateProvenance(artifact, policy));

        if (findings.isEmpty()) {
            String rationale = "三个风险维度均未命中策略 v" + policy.version()
                    + "（漏洞阈值 " + policy.blockSeverity()
                    + "、许可禁止集 " + policy.blockedLicenses()
                    + "、最低 SLSA L" + policy.requiredSlsaLevel()
                    + "、可信构建者要求=" + policy.requireVerifiedBuilder() + "），准予准入。";
            return new Evaluation(DecisionStatus.ADMITTED, List.of(), rationale);
        }

        RiskType primary = findings.stream()
                .map(DecisionFinding::riskType)
                .min(RiskType::compareTo) // 枚举声明顺序即优先级
                .orElseThrow();
        Severity primarySeverity = findings.stream()
                .filter(f -> f.riskType() == primary)
                .map(DecisionFinding::severity)
                .max(Severity::compareTo)
                .orElse(Severity.MEDIUM);

        StringBuilder rationale = new StringBuilder();
        rationale.append("命中 ").append(findings.size()).append(" 条风险，")
                .append("按固定优先级（漏洞>许可>来源）以 ")
                .append(primary).append("(").append(primarySeverity).append(") 为主导风险，结论隔离。全部依据：");
        for (int i = 0; i < findings.size(); i++) {
            DecisionFinding f = findings.get(i);
            rationale.append("\n  ").append(i + 1).append(". [").append(f.riskType())
                    .append("/").append(f.severity()).append("] ")
                    .append(f.ruleId()).append(" - ").append(f.detail());
        }
        return new Evaluation(DecisionStatus.QUARANTINED, List.copyOf(findings), rationale.toString());
    }

    private List<DecisionFinding> evaluateVulnerabilities(ArtifactRecord artifact, Policy policy) {
        List<DecisionFinding> result = new ArrayList<>();
        NormalizedManifest manifest = artifact.manifest();
        List<Vulnerability> all = new ArrayList<>(manifest.declaredVulns());
        for (Component component : manifest.components()) {
            all.addAll(component.vulnerabilities());
        }
        for (Vulnerability vuln : all) {
            if (vuln.severity().compareTo(policy.blockSeverity()) >= 0) {
                result.add(new DecisionFinding(RiskType.VULNERABILITY, vuln.severity(),
                        "VULN-SEVERITY-THRESHOLD",
                        "漏洞 " + vuln.id() + " 等级 " + vuln.severity()
                                + " 达到/超过隔离阈值 " + policy.blockSeverity()
                                + (vuln.cvss() != null ? "（CVSS " + vuln.cvss() + "）" : "")));
            }
        }
        return result;
    }

    private List<DecisionFinding> evaluateLicenses(ArtifactRecord artifact, Policy policy) {
        List<DecisionFinding> result = new ArrayList<>();
        for (License license : artifact.manifest().licenses()) {
            String id = license.id();
            if (policy.blockedLicenses().stream().map(s -> s.toLowerCase(Locale.ROOT))
                    .anyMatch(b -> b.equalsIgnoreCase(id))) {
                result.add(new DecisionFinding(RiskType.LICENSE, Severity.HIGH,
                        "LICENSE-BLOCKED",
                        "许可证 " + id + " 在策略 v" + policy.version() + " 的禁止清单中"));
            } else if (policy.blockCopyleft() && license.copyleft()) {
                result.add(new DecisionFinding(RiskType.LICENSE, Severity.MEDIUM,
                        "LICENSE-COPYLEFT",
                        "许可证 " + id + " 为 Copyleft，策略禁止 Copyleft 许可证"));
            }
        }
        return result;
    }

    private List<DecisionFinding> evaluateProvenance(ArtifactRecord artifact, Policy policy) {
        List<DecisionFinding> result = new ArrayList<>();
        Provenance provenance = artifact.provenance();
        if (provenance == null) {
            result.add(new DecisionFinding(RiskType.PROVENANCE, Severity.HIGH,
                    "PROV-MISSING", "缺少经验签的来源材料，无法满足来源可信度要求"));
            return result;
        }
        if (provenance.slsaLevel() < policy.requiredSlsaLevel()) {
            result.add(new DecisionFinding(RiskType.PROVENANCE, Severity.MEDIUM,
                    "PROV-SLSA-LEVEL",
                    "SLSA 等级 L" + provenance.slsaLevel()
                            + " 低于策略要求的最低 L" + policy.requiredSlsaLevel()));
        }
        if (policy.requireVerifiedBuilder()
                && policy.trustedBuilders().stream().noneMatch(t -> t.equalsIgnoreCase(provenance.builderId()))) {
            result.add(new DecisionFinding(RiskType.PROVENANCE, Severity.HIGH,
                    "PROV-UNTRUSTED-BUILDER",
                    "构建者 " + provenance.builderId() + " 不在可信构建者列表 "
                            + policy.trustedBuilders() + " 中"));
        }
        return result;
    }
}
