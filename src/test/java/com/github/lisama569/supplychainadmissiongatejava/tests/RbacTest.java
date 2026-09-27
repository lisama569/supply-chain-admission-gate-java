package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 角色权限边界测试：越权操作必须以 FORBIDDEN 拒绝。
 */
class RbacTest {

    private GateTestFixtures fx;
    private ArtifactRecord artifact;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        fx = new GateTestFixtures(tempDir);
        artifact = fx.importService.importManifest(GateTestFixtures.analyst(),
                "rbac-import-1", "cyclonedx",
                GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
    }

    @Test
    void guestCannotDoAnything() {
        assertForbidden(() -> fx.importService.importManifest(GateTestFixtures.guest(),
                "x", "cyclonedx", new byte[]{1}, "ab"));
        assertForbidden(() -> fx.gateService.decide(GateTestFixtures.guest(),
                "x", artifact.artifactKey()));
        assertForbidden(() -> fx.gateService.quarantine(GateTestFixtures.guest(),
                "x", artifact.artifactKey(), "r"));
        assertForbidden(() -> fx.policyService.publish(GateTestFixtures.guest(),
                "x", 0, draft()));
        assertForbidden(() -> fx.gateService.override(GateTestFixtures.guest(),
                "x", artifact.artifactKey(), DecisionStatus.ADMITTED, "r"));
    }

    @Test
    void analystCanOnlyImport() {
        // 导入成功（前面已演示），其他操作均拒绝
        assertForbidden(() -> fx.gateService.decide(GateTestFixtures.analyst(),
                "a1", artifact.artifactKey()));
        assertForbidden(() -> fx.gateService.quarantine(GateTestFixtures.analyst(),
                "a2", artifact.artifactKey(), "r"));
        assertForbidden(() -> fx.policyService.publish(GateTestFixtures.analyst(),
                "a3", 0, draft()));
        assertForbidden(() -> fx.gateService.override(GateTestFixtures.analyst(),
                "a4", artifact.artifactKey(), DecisionStatus.ADMITTED, "r"));
    }

    @Test
    void approverCanDecideAndQuarantineButNotPolicyOrOverride() {
        fx.gateService.decide(GateTestFixtures.approver(), "ap1", artifact.artifactKey());
        fx.gateService.quarantine(GateTestFixtures.approver(), "ap2",
                artifact.artifactKey(), "复核发现来源待确认");
        assertForbidden(() -> fx.policyService.publish(GateTestFixtures.approver(),
                "ap3", 0, draft()));
        assertForbidden(() -> fx.gateService.override(GateTestFixtures.approver(),
                "ap4", artifact.artifactKey(), DecisionStatus.ADMITTED, "r"));
    }

    @Test
    void policyAdminCanOnlyPublishPolicy() {
        fx.policyService.publish(GateTestFixtures.policyAdmin(), "pa1", 0, draft());
        assertForbidden(() -> fx.importService.importManifest(GateTestFixtures.policyAdmin(),
                "pa2", "cyclonedx", new byte[]{1}, "ab"));
        assertForbidden(() -> fx.gateService.decide(GateTestFixtures.policyAdmin(),
                "pa3", artifact.artifactKey()));
        assertForbidden(() -> fx.gateService.quarantine(GateTestFixtures.policyAdmin(),
                "pa4", artifact.artifactKey(), "r"));
        assertForbidden(() -> fx.gateService.override(GateTestFixtures.policyAdmin(),
                "pa5", artifact.artifactKey(), DecisionStatus.ADMITTED, "r"));
    }

    @Test
    void onlySecurityOfficerCanOverride() {
        fx.gateService.quarantine(GateTestFixtures.approver(), "of1",
                artifact.artifactKey(), "人工隔离待审");
        var overridden = fx.gateService.override(GateTestFixtures.officer(), "of2",
                artifact.artifactKey(), DecisionStatus.ADMITTED,
                "已取得厂商补充说明并经安全委员会批准");
        assertEquals(DecisionStatus.ADMITTED, overridden.status());
        assertEquals("dave-officer", overridden.overriddenBy());
        System.out.println("[权限边界] 安全官员覆盖成功：" + overridden.decisionId()
                + " -> " + overridden.status() + "，保留依据数=" + overridden.findings().size());
    }

    private static void assertForbidden(org.junit.jupiter.api.function.Executable op) {
        GateException ex = assertThrows(GateException.class, op);
        assertEquals(RejectionReason.FORBIDDEN, ex.reason());
    }

    private static PolicyService.Draft draft() {
        return new PolicyService.Draft(Severity.HIGH, List.of("AGPL-3.0-only"),
                true, 2, true, List.of("pkg:generic/trusted-builder@v1"), "rbac 用策略");
    }
}
