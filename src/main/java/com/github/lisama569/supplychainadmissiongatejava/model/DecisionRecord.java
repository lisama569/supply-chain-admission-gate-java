package com.github.lisama569.supplychainadmissiongatejava.model;

import java.time.Instant;
import java.util.List;

/** Immutable, auditable record of one admission decision. */
public record DecisionRecord(
        String decisionId,
        String idempotencyKey,
        Instant decidedAt,
        long policyVersion,
        Verdict verdict,
        List<RejectReason> reasons,
        List<String> evidence,
        String inputDigest,
        String actor,
        boolean overridden) {
}
