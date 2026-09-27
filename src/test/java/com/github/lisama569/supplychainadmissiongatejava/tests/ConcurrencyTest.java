package com.github.lisama569.supplychainadmissiongatejava.tests;

import com.github.lisama569.supplychainadmissiongatejava.decision.AdmissionDecider;
import com.github.lisama569.supplychainadmissiongatejava.ingest.CsvManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.CycloneDxParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.ManifestIngestor;
import com.github.lisama569.supplychainadmissiongatejava.ingest.SpdxParser;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.Role;
import com.github.lisama569.supplychainadmissiongatejava.policy.Policy;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyStore;
import com.github.lisama569.supplychainadmissiongatejava.provenance.ProvenanceParser;
import com.github.lisama569.supplychainadmissiongatejava.provenance.SignatureVerifier;
import com.github.lisama569.supplychainadmissiongatejava.service.AdmissionGateService;
import com.github.lisama569.supplychainadmissiongatejava.service.AuditLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyTest.class);
    private static final Path SAMPLES = Path.of("samples");
    private static final String ISSUER_KEYS = "acme-release=secret-acme-key";

    @TempDir
    Path tempDir;

    @Test
    void concurrentPolicyPublishesAndSubmissionsStayConsistent() throws Exception {
        PolicyStore policyStore = new PolicyStore();
        AdmissionGateService service = new AdmissionGateService(
                new ManifestIngestor(List.of(
                        new CycloneDxParser(), new SpdxParser(), new CsvManifestParser())),
                new ProvenanceParser(),
                new SignatureVerifier(ISSUER_KEYS),
                new AdmissionDecider(),
                policyStore,
                new AuditLog(tempDir.resolve("audit.log").toString()));

        String manifest = Files.readString(SAMPLES.resolve("manifest-spdx.json"));
        String provenance = Files.readString(SAMPLES.resolve("provenance-valid.json"));

        int publishers = 8;
        int submitters = 16;
        ExecutorService pool = Executors.newFixedThreadPool(publishers + submitters);
        try {
            List<Callable<Policy>> publishTasks = new ArrayList<>();
            for (int i = 0; i < publishers; i++) {
                int n = i;
                publishTasks.add(() -> service.publishPolicy(
                        new Policy(0, n % 2, Set.of("GPL-3.0-only"), Set.of("acme-release")),
                        Role.POLICY_ADMIN, "admin-" + n));
            }
            List<Callable<DecisionRecord>> submitTasks = new ArrayList<>();
            for (int i = 0; i < submitters; i++) {
                int n = i;
                submitTasks.add(() -> service.submit(manifest, provenance,
                        "k-conc-" + n, Role.ADMISSION_OPERATOR, "op-" + n));
            }

            List<Future<Policy>> policyFutures = new ArrayList<>();
            for (Callable<Policy> t : publishTasks) {
                policyFutures.add(pool.submit(t));
            }
            List<Future<DecisionRecord>> decisionFutures = new ArrayList<>();
            for (Callable<DecisionRecord> t : submitTasks) {
                decisionFutures.add(pool.submit(t));
            }

            List<Long> versions = new ArrayList<>();
            for (Future<Policy> f : policyFutures) {
                versions.add(f.get().version());
            }
            // versions are unique and monotonic: exactly 1..publishers
            assertEquals(publishers, versions.stream().distinct().count());
            assertTrue(versions.stream().allMatch(v -> v >= 1 && v <= publishers));

            for (Future<DecisionRecord> f : decisionFutures) {
                DecisionRecord r = f.get();
                // every decision was made against exactly one published version
                assertTrue(r.policyVersion() >= 0 && r.policyVersion() <= publishers,
                        "mixed/unknown policy version " + r.policyVersion());
                log.info("decisionId={} policyVersion={} verdict={} reasons={} digest={}",
                        r.decisionId(), r.policyVersion(), r.verdict(), r.reasons(),
                        r.inputDigest().substring(0, 16));
            }
            // no half-written records: one entry per idempotency key
            assertEquals(submitters, service.history().size());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentDuplicateSubmissionsYieldSingleRecord() throws Exception {
        PolicyStore policyStore = new PolicyStore();
        AdmissionGateService service = new AdmissionGateService(
                new ManifestIngestor(List.of(
                        new CycloneDxParser(), new SpdxParser(), new CsvManifestParser())),
                new ProvenanceParser(),
                new SignatureVerifier(ISSUER_KEYS),
                new AdmissionDecider(),
                policyStore,
                new AuditLog(tempDir.resolve("audit.log").toString()));
        policyStore.publish(new Policy(0, 0, Set.of(), Set.of("acme-release")));

        String manifest = Files.readString(SAMPLES.resolve("manifest-spdx.json"));
        String provenance = Files.readString(SAMPLES.resolve("provenance-valid.json"));

        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<DecisionRecord>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> service.submit(manifest, provenance,
                        "k-same", Role.ADMISSION_OPERATOR, "op")));
            }
            String firstId = futures.get(0).get().decisionId();
            for (Future<DecisionRecord> f : futures) {
                assertEquals(firstId, f.get().decisionId());
            }
            assertEquals(1, service.history().size());
            log.info("concurrent duplicates collapsed to decisionId={}", firstId);
        } finally {
            pool.shutdownNow();
        }
    }
}
