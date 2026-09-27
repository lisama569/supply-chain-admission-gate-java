package com.github.lisama569.supplychainadmissiongatejava.decision;

import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.ProvenanceInfo;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Verdict;
import com.github.lisama569.supplychainadmissiongatejava.policy.Policy;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Deterministic decision engine. Rules (evaluated per artifact, sorted by
 * name for stable output):
 *   - vulnerability count &gt; policy.maxVulnerabilities  =&gt; VULNERABILITY_RISK
 *   - license missing or in policy.bannedLicenses         =&gt; LICENSE_RISK
 *   - provenance issuer not in policy.trustedIssuers      =&gt; UNTRUSTED_SOURCE
 * Combination (fixed precedence, always explainable):
 *   - any VULNERABILITY_RISK or LICENSE_RISK =&gt; REJECT (all reasons listed)
 *   - only UNTRUSTED_SOURCE                  =&gt; QUARANTINE
 *   - no risks                               =&gt; ADMIT
 */
@Component
public class AdmissionDecider {

    public DecisionRecord decide(List<Artifact> artifacts,
                                 ProvenanceInfo provenance,
                                 Policy policy,
                                 String idempotencyKey,
                                 String inputDigest,
                                 String actor) {
        Set<RejectReason> reasons = new LinkedHashSet<>();
        List<String> evidence = new ArrayList<>();

        List<Artifact> sorted = artifacts.stream()
                .sorted(Comparator.comparing(Artifact::name).thenComparing(Artifact::version))
                .toList();

        for (Artifact a : sorted) {
            String id = a.name() + "@" + a.version();
            if (a.vulnerabilities().size() > policy.maxVulnerabilities()) {
                reasons.add(RejectReason.VULNERABILITY_RISK);
                evidence.add(id + ": " + a.vulnerabilities().size() + " vulnerabilities "
                        + a.vulnerabilities() + " exceed max " + policy.maxVulnerabilities());
            }
            if (a.license() == null) {
                reasons.add(RejectReason.LICENSE_RISK);
                evidence.add(id + ": no license declared");
            } else if (policy.bannedLicenses().contains(a.license())) {
                reasons.add(RejectReason.LICENSE_RISK);
                evidence.add(id + ": license '" + a.license() + "' is banned by policy");
            }
        }

        boolean trusted = provenance != null
                && policy.trustedIssuers().contains(provenance.issuer());
        if (!trusted) {
            reasons.add(RejectReason.UNTRUSTED_SOURCE);
            evidence.add("issuer '" + (provenance == null ? null : provenance.issuer())
                    + "' not in policy trustedIssuers " + policy.trustedIssuers());
        }

        Verdict verdict;
        if (reasons.contains(RejectReason.VULNERABILITY_RISK)
                || reasons.contains(RejectReason.LICENSE_RISK)) {
            verdict = Verdict.REJECT;
        } else if (reasons.contains(RejectReason.UNTRUSTED_SOURCE)) {
            verdict = Verdict.QUARANTINE;
        } else {
            verdict = Verdict.ADMIT;
        }

        String decisionId = deterministicId(idempotencyKey, policy.version(), inputDigest);
        return new DecisionRecord(
                decisionId, idempotencyKey, Instant.now(), policy.version(),
                verdict, List.copyOf(reasons), List.copyOf(evidence),
                inputDigest, actor, false);
    }

    public static String deterministicId(String idempotencyKey, long policyVersion, String inputDigest) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] raw = md.digest((idempotencyKey + "|" + policyVersion + "|" + inputDigest)
                    .getBytes(StandardCharsets.UTF_8));
            return UUID.nameUUIDFromBytes(raw).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
