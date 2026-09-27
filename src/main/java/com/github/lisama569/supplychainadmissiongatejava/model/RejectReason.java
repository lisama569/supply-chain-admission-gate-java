package com.github.lisama569.supplychainadmissiongatejava.model;

/** Distinguishable rejection reasons. Nothing fails silently. */
public enum RejectReason {
    MISSING_FIELD,
    UNSUPPORTED_FORMAT_VERSION,
    PROVENANCE_CONFLICT,
    INVALID_SIGNATURE,
    PERMISSION_DENIED,
    VULNERABILITY_RISK,
    LICENSE_RISK,
    UNTRUSTED_SOURCE,
    MALFORMED_INPUT
}
