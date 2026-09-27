package com.github.lisama569.supplychainadmissiongatejava.model;

/** Source / provenance material attached to a manifest submission. */
public record ProvenanceInfo(
        String issuer,
        String repository,
        String signature,
        String signedPayload) {
}
