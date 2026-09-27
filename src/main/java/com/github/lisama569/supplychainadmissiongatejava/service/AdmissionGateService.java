package com.github.lisama569.supplychainadmissiongatejava.service;

import com.github.lisama569.supplychainadmissiongatejava.decision.AdmissionDecider;
import com.github.lisama569.supplychainadmissiongatejava.ingest.IngestException;
import com.github.lisama569.supplychainadmissiongatejava.ingest.ManifestIngestor;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Role;
import com.github.lisama569.supplychainadmissiongatejava.model.Verdict;
import com.github.lisama569.supplychainadmissiongatejava.policy.Policy;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyStore;
import com.github.lisama569.supplychainadmissiongatejava.provenance.ProvenanceParser;
import com.github.lisama569.supplychainadmissiongatejava.provenance.SignatureVerifier;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates ingest, provenance verification, decision, idempotency and
 * audit. Submit/override are serialized so concurrent imports and policy
 * switches never produce half-updated or mixed-version results: each decision
 * is computed against exactly one policy snapshot and appended atomically.
 */
@Service
public class AdmissionGateService {

    private final ManifestIngestor ingestor;
    private final ProvenanceParser provenanceParser;
    private final SignatureVerifier signatureVerifier;
    private final AdmissionDecider decider;
    private final PolicyStore policyStore;
    private final AuditLog auditLog;

    public AdmissionGateService(ManifestIngestor ingestor,
                                ProvenanceParser provenanceParser,
                                SignatureVerifier signatureVerifier,
                                AdmissionDecider decider,
                                PolicyStore policyStore,
                                AuditLog auditLog) {
        this.ingestor = ingestor;
        this.provenanceParser = provenanceParser;
        this.signatureVerifier = signatureVerifier;
        this.decider = decider;
        this.policyStore = policyStore;
        this.auditLog = auditLog;
    }

    public synchronized DecisionRecord submit(String manifestContent,
                                              String provenanceJson,
                                              String idempotencyKey,
                                              Role role,
                                              String actor) {
        if (role == null || !role.allows(Role.Operation.IMPORT)) {
            throw new PermissionDeniedException(
                    "role " + role + " may not import manifests (operation IMPORT)");
        }
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new IngestException(RejectReason.MISSING_FIELD, "idempotencyKey is required");
        }
        // Idempotent replay: same key returns the original recorded decision.
        Optional<DecisionRecord> existing = auditLog.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            return existing.get();
        }

        String inputDigest = digest(manifestContent, provenanceJson);
        Policy policy = policyStore.current(); // single atomic snapshot
        try {
            ManifestIngestor.IngestResult ingested = ingestor.ingest(manifestContent);
            ProvenanceParser.ParsedProvenance provenance = provenanceParser.parse(provenanceJson);
            provenanceParser.checkConsistency(provenance, ingested.artifacts());
            if (!signatureVerifier.verify(provenance.info())) {
                throw new IngestException(RejectReason.INVALID_SIGNATURE,
                        "signature invalid or issuer '" + provenance.info().issuer() + "' unknown");
            }
            DecisionRecord record = decider.decide(
                    ingested.artifacts(), provenance.info(), policy,
                    idempotencyKey, inputDigest, actor);
            auditLog.append(record);
            return record;
        } catch (IngestException e) {
            // Rejected inputs are also recorded so the refusal is traceable.
            DecisionRecord record = new DecisionRecord(
                    AdmissionDecider.deterministicId(idempotencyKey, policy.version(), inputDigest),
                    idempotencyKey, Instant.now(), policy.version(),
                    Verdict.REJECT, List.of(e.reason()), List.of(e.getMessage()),
                    inputDigest, actor, false);
            auditLog.append(record);
            return record;
        }
    }

    public synchronized DecisionRecord override(String decisionId,
                                                Role role,
                                                String actor,
                                                String justification) {
        if (role == null || !role.allows(Role.Operation.OVERRIDE)) {
            throw new PermissionDeniedException(
                    "role " + role + " may not override decisions (operation OVERRIDE)");
        }
        String overrideKey = "override:" + decisionId;
        Optional<DecisionRecord> existing = auditLog.findByIdempotencyKey(overrideKey);
        if (existing.isPresent()) {
            return existing.get(); // idempotent
        }
        DecisionRecord original = auditLog.findById(decisionId)
                .orElseThrow(() -> new IngestException(
                        RejectReason.MISSING_FIELD, "no decision with id " + decisionId));
        Policy policy = policyStore.current();
        DecisionRecord record = new DecisionRecord(
                AdmissionDecider.deterministicId(overrideKey, policy.version(), original.inputDigest()),
                overrideKey, Instant.now(), original.policyVersion(),
                Verdict.ADMIT,
                original.reasons(),
                append(original.evidence(), "OVERRIDE by " + actor + ": " + justification),
                original.inputDigest(), actor, true);
        auditLog.append(record);
        return record;
    }

    public synchronized Policy publishPolicy(Policy requested, Role role, String actor) {
        if (role == null || !role.allows(Role.Operation.POLICY_PUBLISH)) {
            throw new PermissionDeniedException(
                    "role " + role + " may not publish policies (operation POLICY_PUBLISH)");
        }
        return policyStore.publish(requested);
    }

    public Policy currentPolicy() {
        return policyStore.current();
    }

    public Optional<DecisionRecord> findDecision(String decisionId) {
        return auditLog.findById(decisionId);
    }

    public List<DecisionRecord> history() {
        return auditLog.all();
    }

    private static List<String> append(List<String> list, String item) {
        var copy = new java.util.ArrayList<>(list);
        copy.add(item);
        return List.copyOf(copy);
    }

    static String digest(String manifestContent, String provenanceJson) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((manifestContent == null ? "" : manifestContent).getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update((provenanceJson == null ? "" : provenanceJson).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(md.digest());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
