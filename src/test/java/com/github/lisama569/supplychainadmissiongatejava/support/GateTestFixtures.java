package com.github.lisama569.supplychainadmissiongatejava.support;

import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import com.github.lisama569.supplychainadmissiongatejava.decision.DecisionEngine;
import com.github.lisama569.supplychainadmissiongatejava.gate.GateService;
import com.github.lisama569.supplychainadmissiongatejava.importing.ImportService;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.parse.ManifestParserRegistry;
import com.github.lisama569.supplychainadmissiongatejava.parse.ProvenanceParser;
import com.github.lisama569.supplychainadmissiongatejava.parse.CycloneDxManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.parse.InternalManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.parse.SpdxManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.persist.ArtifactRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.DecisionRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.IdempotencyRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.JsonStore;
import com.github.lisama569.supplychainadmissiongatejava.persist.PolicyRepository;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService;
import com.github.lisama569.supplychainadmissiongatejava.rbac.AccessControl;
import com.github.lisama569.supplychainadmissiongatejava.security.HmacSigner;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.io.TempDir;

/** 测试夹具：隔离的数据目录、直接 new 出来的服务对象、样本读取与统一日志。 */
public final class GateTestFixtures {

    public static final Path SAMPLES = Paths.get("samples");

    public final JsonStore store;
    public final HmacSigner signer;
    public final ArtifactRepository artifacts;
    public final PolicyRepository policies;
    public final DecisionRepository decisions;
    public final IdempotencyRepository idempotency;
    public final AccessControl accessControl;
    public final ImportService importService;
    public final PolicyService policyService;
    public final GateService gateService;
    public final DecisionEngine engine;

    public GateTestFixtures(Path tempDir) {
        this.store = new JsonStore(tempDir);
        byte[] key;
        try {
            key = Files.readAllBytes(SAMPLES.resolve("keys/hmac.key"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        this.signer = new HmacSigner(key);
        this.artifacts = new ArtifactRepository(store);
        this.policies = new PolicyRepository(store);
        this.decisions = new DecisionRepository(store);
        this.idempotency = new IdempotencyRepository(store);
        this.accessControl = new AccessControl();
        this.engine = new DecisionEngine();
        ManifestParserRegistry registry = new ManifestParserRegistry(List.of(
                new SpdxManifestParser(), new CycloneDxManifestParser(), new InternalManifestParser()));
        this.importService = new ImportService(registry, new ProvenanceParser(),
                artifacts, idempotency, policies, accessControl, signer);
        this.policyService = new PolicyService(policies, idempotency, accessControl);
        this.gateService = new GateService(artifacts, decisions, policies, idempotency,
                engine, accessControl);
    }

    public static UserContext analyst() {
        return new UserContext("alice-analyst", com.github.lisama569.supplychainadmissiongatejava.common.Role.ANALYST);
    }

    public static UserContext approver() {
        return new UserContext("bob-approver", com.github.lisama569.supplychainadmissiongatejava.common.Role.APPROVER);
    }

    public static UserContext policyAdmin() {
        return new UserContext("carol-policy", com.github.lisama569.supplychainadmissiongatejava.common.Role.POLICY_ADMIN);
    }

    public static UserContext officer() {
        return new UserContext("dave-officer", com.github.lisama569.supplychainadmissiongatejava.common.Role.SECURITY_OFFICER);
    }

    public static UserContext guest() {
        return new UserContext("erin-guest", com.github.lisama569.supplychainadmissiongatejava.common.Role.GUEST);
    }

    public static byte[] sample(String category, String name) {
        try {
            return Files.readAllBytes(SAMPLES.resolve(category).resolve(name));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static String signature(String category, String name) {
        try {
            return Files.readString(SAMPLES.resolve(category).resolve(name + ".sig"),
                    StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** 在单测日志中打印输入摘要、策略版本与判定依据。 */
    public static void logDecision(String caseName, byte[] input, DecisionRecord record) {
        String digest = record.artifactDigest() == null ? "-" : record.artifactDigest();
        System.out.println("==== 判定日志 [" + caseName + "] ====");
        System.out.println("输入摘要(sha256)=" + digest
                + ", 输入字节数=" + (input == null ? 0 : input.length)
                + ", 策略版本=v" + record.policyVersion()
                + ", 最终状态=" + record.status());
        int i = 1;
        for (var finding : record.findings()) {
            System.out.println("  依据" + (i++) + ": [" + finding.riskType() + "/"
                    + finding.severity() + "] " + finding.ruleId() + " -> " + finding.detail());
        }
        System.out.println("  解释: " + record.rationale().replace("\n", "\n  "));
        System.out.println("==== /判定日志 ====");
    }
}
