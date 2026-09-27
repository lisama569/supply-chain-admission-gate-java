package com.github.lisama569.supplychainadmissiongatejava.policy;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the active policy. Publishes are atomic: a reader either sees the old
 * policy or the new one, never a mix. Versions must increase monotonically.
 */
@Component
public class PolicyStore {

    private final AtomicReference<Policy> current = new AtomicReference<>(Policy.initial());

    public Policy current() {
        return current.get();
    }

    /**
     * Publishes a new policy. The given policy's version is ignored; the store
     * assigns the next monotonic version so concurrent publishers can never
     * produce duplicate or regressive versions.
     */
    public Policy publish(Policy requested) {
        return current.updateAndGet(prev -> new Policy(
                prev.version() + 1,
                requested.maxVulnerabilities(),
                requested.bannedLicenses(),
                requested.trustedIssuers()));
    }
}
