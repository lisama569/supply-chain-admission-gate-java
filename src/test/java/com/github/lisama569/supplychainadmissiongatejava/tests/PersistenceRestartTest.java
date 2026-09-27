package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 服务“重启”后历史判定依据仍可追溯：
 * 丢弃内存中的服务对象、用同一数据目录重新装配，制品、策略版本、判定记录必须完整恢复。
 */
class PersistenceRestartTest {

    @Test
    void historySurvivesRestart(@TempDir Path dataDir) {
        GateTestFixtures first = new GateTestFixtures(dataDir);
        ArtifactRecord artifact = first.importService.importManifest(GateTestFixtures.analyst(),
                "persist-import", "spdx",
                GateTestFixtures.sample("valid", "spdx-2.3.json"),
                GateTestFixtures.signature("valid", "spdx-2.3.json"));
        first.importService.attachProvenance(GateTestFixtures.analyst(), "persist-prov",
                artifact.artifactKey(),
                GateTestFixtures.sample("valid", "provenance-spdx-v1.json"),
                GateTestFixtures.signature("valid", "provenance-spdx-v1.json"));
        first.policyService.publish(GateTestFixtures.policyAdmin(), "persist-pub", 0,
                new PolicyService.Draft(Severity.CRITICAL,
                        List.of("AGPL-3.0-only"), false, 2, true,
                        List.of("pkg:generic/trusted-builder@v1"), "持久化策略"));
        DecisionRecord decision = first.gateService.decide(GateTestFixtures.approver(),
                "persist-dec", artifact.artifactKey());
        DecisionRecord quarantined = first.gateService.quarantine(GateTestFixtures.approver(),
                "persist-qtn", artifact.artifactKey(), "重启前人工隔离，用于验证追溯");
        DecisionRecord overridden = first.gateService.override(GateTestFixtures.officer(),
                "persist-ovr", artifact.artifactKey(), DecisionStatus.ADMITTED,
                "重启前安全覆盖，用于验证追溯");

        // 模拟重启：同一数据目录重新装配全部组件
        GateTestFixtures restarted = new GateTestFixtures(dataDir);

        ArtifactRecord restoredArtifact = restarted.artifacts.find(artifact.artifactKey()).orElseThrow();
        assertEquals(artifact.digestHex(), restoredArtifact.digestHex());
        assertNotNull(restoredArtifact.provenance(), "来源材料必须随制品一起恢复");
        assertEquals("pkg:generic/trusted-builder@v1",
                restoredArtifact.provenance().builderId());

        Policy current = restarted.policyService.current();
        assertEquals(1, current.version());
        assertEquals(Severity.CRITICAL, current.blockSeverity());
        assertEquals("carol-policy", current.publishedBy());

        DecisionRecord restoredDecision = restarted.gateService.getDecision(decision.decisionId());
        assertEquals(decision.rationale(), restoredDecision.rationale());
        assertEquals(decision.findings().size(), restoredDecision.findings().size());
        assertEquals(decision.policyVersion(), restoredDecision.policyVersion());

        DecisionRecord restoredOverride = restarted.gateService.getDecision(overridden.decisionId());
        assertEquals(DecisionStatus.ADMITTED, restoredOverride.status());
        assertEquals("dave-officer", restoredOverride.overriddenBy());
        assertTrue(restoredOverride.findings().size() >= quarantined.findings().size(),
                "覆盖记录必须保留被覆盖结论的依据");

        List<DecisionRecord> timeline = restarted.gateService.history(artifact.artifactKey());
        assertEquals(List.of("dec-persist-dec", "qtn-persist-qtn", "ovr-persist-ovr"),
                timeline.stream().map(DecisionRecord::decisionId).toList(),
                "时间线顺序必须可重建");
        System.out.println("[重启追溯] 恢复时间线="
                + timeline.stream().map(d -> d.decisionId() + ":" + d.status()).toList());
        System.out.println("[重启追溯] 自动判定依据数=" + restoredDecision.findings().size()
                + "，策略版本=v" + restoredDecision.policyVersion());
    }

    private static void assertTrue(boolean condition, String message) {
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
