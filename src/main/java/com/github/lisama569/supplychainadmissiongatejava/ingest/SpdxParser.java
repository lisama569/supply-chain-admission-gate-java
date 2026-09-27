package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** SPDX JSON (2.x) parser. */
@Component
public class SpdxParser implements ManifestParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public ManifestFormat format() {
        return ManifestFormat.SPDX_JSON;
    }

    @Override
    public boolean supports(String content) {
        try {
            JsonNode root = MAPPER.readTree(content);
            return root != null && root.isObject()
                    && root.path("spdxVersion").asText("").startsWith("SPDX-");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public List<Artifact> parse(String content) {
        final JsonNode root;
        try {
            root = MAPPER.readTree(content);
        } catch (Exception e) {
            throw new IngestException(RejectReason.MALFORMED_INPUT, "invalid JSON: " + e.getMessage());
        }
        String spdxVersion = root.path("spdxVersion").asText(null);
        if (spdxVersion == null) {
            throw new IngestException(RejectReason.MISSING_FIELD, "SPDX: missing spdxVersion");
        }
        if (!spdxVersion.startsWith("SPDX-2.")) {
            throw new IngestException(RejectReason.UNSUPPORTED_FORMAT_VERSION,
                    "SPDX version " + spdxVersion + " not supported (only SPDX-2.x)");
        }
        JsonNode packages = root.path("packages");
        if (!packages.isArray() || packages.isEmpty()) {
            throw new IngestException(RejectReason.MISSING_FIELD, "SPDX: missing or empty packages");
        }
        List<Artifact> artifacts = new ArrayList<>();
        int idx = 0;
        for (JsonNode p : packages) {
            idx++;
            String name = p.path("name").asText(null);
            String version = p.path("versionInfo").asText(null);
            if (name == null || name.isBlank()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "SPDX: package #" + idx + " missing name");
            }
            if (version == null || version.isBlank()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "SPDX: package '" + name + "' missing versionInfo");
            }
            String license = p.path("licenseConcluded").asText(null);
            if ("NOASSERTION".equals(license)) {
                license = null;
            }
            String purl = null;
            for (JsonNode ref : p.path("externalRefs")) {
                if ("purl".equals(ref.path("referenceType").asText())) {
                    purl = ref.path("referenceLocator").asText(null);
                    break;
                }
            }
            String hash = null;
            for (JsonNode chk : p.path("checksums")) {
                if ("SHA256".equalsIgnoreCase(chk.path("algorithm").asText())) {
                    hash = chk.path("checksumValue").asText(null);
                    break;
                }
            }
            String supplier = p.path("supplier").asText(null);
            if (supplier != null && supplier.startsWith("Organization:")) {
                supplier = supplier.substring("Organization:".length()).trim();
            }
            List<String> vulns = new ArrayList<>();
            for (JsonNode v : p.path("vulnerabilities")) {
                String id = v.asText(null);
                if (id != null) {
                    vulns.add(id);
                }
            }
            artifacts.add(new Artifact(name, version, purl, license, List.copyOf(vulns), supplier, hash));
        }
        return List.copyOf(artifacts);
    }
}
