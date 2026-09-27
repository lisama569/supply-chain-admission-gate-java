package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.List;

/** Normalized artifact record produced from any supported manifest format. */
public record Artifact(
        String name,
        String version,
        String purl,
        String license,
        List<String> vulnerabilities,
        String supplier,
        String hashSha256) {
}
