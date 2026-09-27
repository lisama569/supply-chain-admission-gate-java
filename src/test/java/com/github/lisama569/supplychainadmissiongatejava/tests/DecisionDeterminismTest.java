package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.RiskType;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 判定确定性与可解释性测试：
 * 同样输入 + 同一策略版本必须得到同样结论；漏洞/许可/来源三维度同时命中时，
 * 结论由固定优先级决定（漏洞主导），且全部依据都被保留。
 */
class DecisionDeterminismTest {

    private GateTestFixtures fx;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        fx = new GateTestFixtures(tempDir);
    }

    @Test
    void cleanArtifactWithTrustedProvenanceIsAdmitted() {
        ArtifactRecord artifact = importCleanCdx();
        ArtifactRecord withProv = fx.importService.attachProvenance(GateTestFixtures.analyst(),
                "prov-clean", artifact.artifactKey(),
                GateTestFixtures.sample("valid", "provenance-cyclonedx-v1.json"),
                GateTestFixtures.signature("valid", "provenance-cyclonedx-v1.json"));
        DecisionRecord decision = fx.gateService.decide(GateTestFixtures.approver(),
                "dec-clean-1", artifact.artifactKey());
        GateTestFixtures.logDecision("clean-cdx", null, decision);
        assertEquals(DecisionStatus.ADMITTED, decision.status());
        assertEquals(0, decision.findings().size());
        assertTrue(decision.rationale().contains("准予准入"));
    }

    @Test
    void allThreeRiskDimensionsHit_butVulnerabilityDeterminesOutcome() throws Exception {
        ArtifactRecord artifact = importBilling();
        fx.importService.attachProvenance(GateTestFixtures.analyst(),
                "prov-internal", artifact.artifactKey(),
                GateTestFixtures.sample("valid", "provenance-internal-v1.json"),
                GateTestFixtures.signature("valid", "provenance-internal-v1.json"));

        DecisionRecord first = fx.gateService.decide(GateTestFixtures.approver(),
                "dec-multi-1", artifact.artifactKey());
        GateTestFixtures.logDecision("three-risks",
                GateTestFixtures.sample("valid", "manifest-v1.json"), first);

        assertEquals(DecisionStatus.QUARANTINED, first.status());
        boolean hasVuln = first.findings().stream().anyMatch(f -> f.riskType() == RiskType.VULNERABILITY);
        boolean hasLicense = first.findings().stream().anyMatch(f -> f.riskType() == RiskType.LICENSE);
        boolean hasProv = first.findings().stream().anyMatch(f -> f.riskType() == RiskType.PROVENANCE);
        assertTrue(hasVuln && hasLicense && hasProv, "三个维度的依据都应保留");
        assertTrue(first.rationale().contains("VULNERABILITY"),
                "最终结论必须由漏洞维度主导，解释中应明确优先级");
        assertTrue(first.rationale().contains("CVE-2022-25845"));
        assertTrue(first.rationale().contains("AGPL-3.0-only"));
        assertTrue(first.rationale().contains("L1") || first.rationale().contains("local-laptop"));

        // 可复现：另一个全新数据目录 + 同样输入，结论与依据完全一致
        GateTestFixtures second = new GateTestFixtures(
                java.nio.file.Files.createTempDirectory("gate-repro-2-"));
        ArtifactRecord artifact2 = second.importService.importManifest(GateTestFixtures.analyst(),
                "dec-multi-1", "internal",
                GateTestFixtures.sample("valid", "manifest-v1.json"),
                GateTestFixtures.signature("valid", "manifest-v1.json"));
        second.importService.attachProvenance(GateTestFixtures.analyst(),
                "prov-internal", artifact2.artifactKey(),
                GateTestFixtures.sample("valid", "provenance-internal-v1.json"),
                GateTestFixtures.signature("valid", "provenance-internal-v1.json"));
        DecisionRecord again = second.gateService.decide(GateTestFixtures.approver(),
                "dec-multi-1", artifact2.artifactKey());
        assertEquals(first.status(), again.status());
        assertEquals(first.findings().size(), again.findings().size());
        assertEquals(first.rationale(), again.rationale());
        assertEquals(first.policyVersion(), again.policyVersion());
    }

    @Test
    void missingProvenanceIsQuarantinedAsProvenanceRisk() {
        ArtifactRecord spdx = importSpdxWithoutProvenance();
        DecisionRecord decision = fx.gateService.decide(GateTestFixtures.approver(),
                "dec-no-prov", spdx.artifactKey());
        GateTestFixtures.logDecision("no-provenance",
                GateTestFixtures.sample("valid", "spdx-2.3.json"), decision);
        assertEquals(DecisionStatus.QUARANTINED, decision.status());
        // 漏洞 CRITICAL 仍优先于“缺少来源”
        assertEquals(RiskType.VULNERABILITY, decision.findings().get(0).riskType());
        assertTrue(decision.findings().stream()
                .anyMatch(f -> f.ruleId().equals("PROV-MISSING")));
    }

    @Test
    void policyVersionChangesOutcomeAndIsRecorded() {
        ArtifactRecord spdx = importSpdxWithProvenance();
        DecisionRecord strict = fx.gateService.decide(GateTestFixtures.approver(),
                "dec-policy-strict", spdx.artifactKey());
        assertEquals(DecisionStatus.QUARANTINED, strict.status());
        assertEquals(0, strict.policyVersion());

        // 放宽漏洞阈值为 CRITICAL 不变（log4j 是 CRITICAL 仍命中）；改为仅 CRITICAL 且……
        // 这里发布：blockSeverity=CRITICAL、不禁止 copyleft、SLSA=1、不要求可信 builder
        fx.policyService.publish(GateTestFixtures.policyAdmin(), "pub-relax-1", 0,
                new com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService.Draft(
                        com.github.lisama569.supplychainadmissiongatejava.model.Severity.CRITICAL,
                        java.util.List.of("AGPL-3.0-only", "AGPL-3.0-or-later"),
                        false, 1, false,
                        java.util.List.of("pkg:generic/trusted-builder@v1"), "放宽策略"));

        // 同一制品，log4j 是 CRITICAL 仍命中 -> 仍隔离，但记录的策略版本变为 1，且不再有许可依据
        DecisionRecord relaxed = fx.gateService.decide(GateTestFixtures.approver(),
                "dec-policy-relaxed", spdx.artifactKey());
        GateTestFixtures.logDecision("policy-v1",
                GateTestFixtures.sample("valid", "spdx-2.3.json"), relaxed);
        assertEquals(1, relaxed.policyVersion());
        assertEquals(DecisionStatus.QUARANTINED, relaxed.status());
        assertTrue(relaxed.findings().stream().anyMatch(f -> f.ruleId().equals("LICENSE-BLOCKED")),
                "AGPL 仍在禁止清单，应有许可依据；放宽仅关闭了 copyleft 兜底规则");
        assertTrue(relaxed.findings().stream().noneMatch(f -> f.ruleId().equals("LICENSE-COPYLEFT")),
                "blockCopyleft=false 后不应再有 copyleft 兜底依据");
        assertNotEquals(strict.policyVersion(), relaxed.policyVersion());
    }

    private ArtifactRecord importCleanCdx() {
        return fx.importService.importManifest(GateTestFixtures.analyst(), "clean-cdx-1",
                "cyclonedx", GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
    }

    private ArtifactRecord importBilling() {
        return fx.importService.importManifest(GateTestFixtures.analyst(), "billing-1",
                "internal", GateTestFixtures.sample("valid", "manifest-v1.json"),
                GateTestFixtures.signature("valid", "manifest-v1.json"));
    }

    private ArtifactRecord importSpdxWithoutProvenance() {
        return fx.importService.importManifest(GateTestFixtures.analyst(), "spdx-noprov-1",
                "spdx", GateTestFixtures.sample("valid", "spdx-2.3.json"),
                GateTestFixtures.signature("valid", "spdx-2.3.json"));
    }

    private ArtifactRecord importSpdxWithProvenance() {
        ArtifactRecord a = importSpdxWithoutProvenance();
        return fx.importService.attachProvenance(GateTestFixtures.analyst(), "spdx-prov-1",
                a.artifactKey(), GateTestFixtures.sample("valid", "provenance-spdx-v1.json"),
                GateTestFixtures.signature("valid", "provenance-spdx-v1.json"));
    }
}
