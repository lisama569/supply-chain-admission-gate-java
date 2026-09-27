package com.github.lisama569.supplychainadmissiongatejava.policy;

import java.util.Set;

/** Versioned admission policy. Immutable once published. */
public record Policy(
        long version,
        int maxVulnerabilities,
        Set<String> bannedLicenses,
        Set<String> trustedIssuers) {

    public static Policy initial() {
        return new Policy(0L, 0, Set.of(), Set.of());
    }
}
