package com.github.lisama569.supplychainadmissiongatejava.tests;

import com.github.lisama569.supplychainadmissiongatejava.decision.AdmissionDecider;
import com.github.lisama569.supplychainadmissiongatejava.ingest.CsvManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.CycloneDxParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.ManifestIngestor;
import com.github.lisama569.supplychainadmissiongatejava.ingest.SpdxParser;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Role;
import com.github.lisama569.supplychainadmissiongatejava.model.Verdict;
import com.github.lisama569.supplychainadmissiongatejava.policy.Policy;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyStore;
import com.github.lisama569.supplychainadmissiongatejava.provenance.ProvenanceParser;
import com.github.lisama569.supplychainadmissiongatejava.provenance.SignatureVerifier;
import com.github.lisama569.supplychainadmissiongatejava.service.AdmissionGateService;
import com.github.lisama569.supplychainadmissiongatejava.service.AuditLog;
import com.github.lisama569.supplychainadmissiongatejava.service.PermissionDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdmissionGateServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AdmissionGateServiceTest.class);
    private static final Path SAMPLES = Path.of("samples");
    private static final String ISSUER_KEYS = "acme-release=secret-acme-key,evil-corp=secret-evil-key";

    @TempDir
    Path tempDir;

    private PolicyStore policyStore;
    private AdmissionGateService service;
    private Path auditFile;

    @BeforeEach
    void setUp() {
        auditFile = tempDir.resolve("audit.log");
        policyStore = new PolicyStore();
        service = newService(auditFile, policyStore);
        // baseline policy v1: no vulns allowed, GPL banned, acme-release trusted
        policyStore.publish(new Policy(0, 0,
                Set.of("GPL-3.0-only", "WTFPL"), Set.of("acme-release")));
    }

    private static AdmissionGateService newService(Path auditFile, PolicyStore policyStore) {
        return new AdmissionGateService(
                new ManifestIngestor(List.of(
                        new CycloneDxParser(), new SpdxParser(), new CsvManifestParser())),
                new ProvenanceParser(),
                new SignatureVerifier(ISSUER_KEYS),
                new AdmissionDecider(),
                policyStore,
                new AuditLog(auditFile.toString()));
    }

    private static String sample(String name) throws IOException {
        return Files.readString(SAMPLES.resolve(name));
    }

    private static void logDecision(String label, DecisionRecord r) {
        log.info("[{}] decisionId={} policyVersion={} verdict={} reasons={} inputDigest={} evidence={}",
                label, r.decisionId(), r.policyVersion(), r.verdict(), r.reasons(),
                r.inputDigest().substring(0, 16), r.evidence());
    }

    @Test
    void admitsCleanArtifactFromTrustedSource() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-spdx.json"),
                sample("provenance-valid.json"), "k-admit", Role.ADMISSION_OPERATOR, "alice");
        logDecision("admit", r);
        assertEquals(Verdict.ADMIT, r.verdict());
        assertTrue(r.reasons().isEmpty());
        assertEquals(1L, r.policyVersion());
    }

    @Test
    void rejectsVulnerabilityAndLicenseRiskWithDistinctReasons() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-cyclonedx.json"),
                sample("provenance-valid.json"), "k-risk", Role.ADMISSION_OPERATOR, "alice");
        logDecision("risk", r);
        assertEquals(Verdict.REJECT, r.verdict());
        assertTrue(r.reasons().contains(RejectReason.VULNERABILITY_RISK));
        assertTrue(r.reasons().contains(RejectReason.LICENSE_RISK));
    }

    @Test
    void multiHitArtifactYieldsDeterministicExplainableVerdict() throws IOException {
        // CSV risky-lib: 2 vulns + banned license; provenance issuer untrusted under a
        // second policy -> all three risk categories hit at once.
        policyStore.publish(new Policy(0, 0,
                Set.of("WTFPL"), Set.of("someone-else")));
        DecisionRecord r1 = service.submit(sample("manifest.csv"),
                sample("provenance-valid.json"), "k-multi", Role.ADMISSION_OPERATOR, "alice");
        DecisionRecord r2 = service.submit(sample("manifest.csv"),
                sample("provenance-valid.json"), "k-multi-2", Role.ADMISSION_OPERATOR, "alice");
        logDecision("multi-1", r1);
        logDecision("multi-2", r2);
        assertEquals(Verdict.REJECT, r1.verdict());
        assertTrue(r1.reasons().containsAll(List.of(
                RejectReason.VULNERABILITY_RISK, RejectReason.LICENSE_RISK,
                RejectReason.UNTRUSTED_SOURCE)));
        // reproducible: same input + same policy version => same verdict & reasons
        assertEquals(r1.verdict(), r2.verdict());
        assertEquals(r1.reasons(), r2.reasons());
        assertEquals(r1.evidence(), r2.evidence());
    }

    @Test
    void rejectsInvalidSignature() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-spdx.json"),
                sample("provenance-invalid-signature.json"), "k-badsig",
                Role.ADMISSION_OPERATOR, "alice");
        logDecision("bad-signature", r);
        assertEquals(Verdict.REJECT, r.verdict());
        assertEquals(List.of(RejectReason.INVALID_SIGNATURE), r.reasons());
    }

    @Test
    void rejectsProvenanceConflict() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-spdx.json"),
                sample("provenance-conflict.json"), "k-conflict",
                Role.ADMISSION_OPERATOR, "alice");
        logDecision("conflict", r);
        assertEquals(Verdict.REJECT, r.verdict());
        assertEquals(List.of(RejectReason.PROVENANCE_CONFLICT), r.reasons());
    }

    @Test
    void rejectsMissingFieldWithDistinctReason() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-missing-field.json"),
                sample("provenance-valid.json"), "k-missing",
                Role.ADMISSION_OPERATOR, "alice");
        logDecision("missing-field", r);
        assertEquals(Verdict.REJECT, r.verdict());
        assertEquals(List.of(RejectReason.MISSING_FIELD), r.reasons());
    }

    @Test
    void deniesUnauthorizedOperations() throws IOException {
        // POLICY_ADMIN may not import
        assertThrows(PermissionDeniedException.class, () -> service.submit(
                sample("manifest-spdx.json"), sample("provenance-valid.json"),
                "k-denied", Role.POLICY_ADMIN, "mallory"));
        // ADMISSION_OPERATOR may not publish policy
        assertThrows(PermissionDeniedException.class, () -> service.publishPolicy(
                new Policy(0, 5, Set.of(), Set.of()), Role.ADMISSION_OPERATOR, "mallory"));
        // QUARANTINE_OPERATOR may not override
        DecisionRecord r = service.submit(sample("manifest-cyclonedx.json"),
                sample("provenance-valid.json"), "k-for-override",
                Role.ADMISSION_OPERATOR, "alice");
        assertThrows(PermissionDeniedException.class, () -> service.override(
                r.decisionId(), Role.QUARANTINE_OPERATOR, "mallory", "try"));
        log.info("permission boundaries enforced for IMPORT/POLICY_PUBLISH/OVERRIDE");
    }

    @Test
    void overrideAdmitsRejectedDecisionIdempotently() throws IOException {
        DecisionRecord rejected = service.submit(sample("manifest-cyclonedx.json"),
                sample("provenance-valid.json"), "k-ovr", Role.ADMISSION_OPERATOR, "alice");
        assertEquals(Verdict.REJECT, rejected.verdict());
        DecisionRecord o1 = service.override(rejected.decisionId(),
                Role.OVERRIDE_ADMIN, "bob", "accepted risk, ticket SEC-42");
        DecisionRecord o2 = service.override(rejected.decisionId(),
                Role.OVERRIDE_ADMIN, "bob", "accepted risk, ticket SEC-42");
        logDecision("override", o1);
        assertEquals(Verdict.ADMIT, o1.verdict());
        assertTrue(o1.overridden());
        assertEquals(o1.decisionId(), o2.decisionId()); // idempotent
    }

    @Test
    void duplicateSubmissionIsIdempotent() throws IOException {
        String manifest = sample("manifest-spdx.json");
        String provenance = sample("provenance-valid.json");
        DecisionRecord r1 = service.submit(manifest, provenance, "k-dup",
                Role.ADMISSION_OPERATOR, "alice");
        DecisionRecord r2 = service.submit(manifest, provenance, "k-dup",
                Role.ADMISSION_OPERATOR, "alice");
        logDecision("dup-1", r1);
        logDecision("dup-2", r2);
        assertEquals(r1.decisionId(), r2.decisionId());
        long count = service.history().stream()
                .filter(d -> d.idempotencyKey().equals("k-dup")).count();
        assertEquals(1, count);
    }

    @Test
    void historySurvivesRestart() throws IOException {
        DecisionRecord r = service.submit(sample("manifest-spdx.json"),
                sample("provenance-valid.json"), "k-restart",
                Role.ADMISSION_OPERATOR, "alice");
        // simulate restart: brand-new service reading the same audit file
        AdmissionGateService restarted = newService(auditFile, policyStore);
        var found = restarted.findDecision(r.decisionId());
        assertTrue(found.isPresent());
        assertEquals(r.verdict(), found.get().verdict());
        assertEquals(r.evidence(), found.get().evidence());
        assertEquals(r.policyVersion(), found.get().policyVersion());
        logDecision("after-restart", found.get());
    }
}
