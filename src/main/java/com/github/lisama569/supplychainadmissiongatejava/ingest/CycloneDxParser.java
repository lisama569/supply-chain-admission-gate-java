package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CycloneDX JSON (spec 1.x) parser. */
@Component
public class CycloneDxParser implements ManifestParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public ManifestFormat format() {
        return ManifestFormat.CYCLONEDX_JSON;
    }

    @Override
    public boolean supports(String content) {
        try {
            JsonNode root = MAPPER.readTree(content);
            return root != null && root.isObject()
                    && "CycloneDX".equals(root.path("bomFormat").asText(null));
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
        String specVersion = root.path("specVersion").asText(null);
        if (specVersion == null) {
            throw new IngestException(RejectReason.MISSING_FIELD, "CycloneDX: missing specVersion");
        }
        if (!specVersion.startsWith("1.")) {
            throw new IngestException(RejectReason.UNSUPPORTED_FORMAT_VERSION,
                    "CycloneDX specVersion " + specVersion + " not supported (only 1.x)");
        }
        JsonNode components = root.path("components");
        if (!components.isArray() || components.isEmpty()) {
            throw new IngestException(RejectReason.MISSING_FIELD, "CycloneDX: missing or empty components");
        }

        // map bom-ref -> CVE ids
        Map<String, List<String>> vulnsByRef = new LinkedHashMap<>();
        for (JsonNode vuln : root.path("vulnerabilities")) {
            String cve = vuln.path("id").asText(null);
            if (cve == null) {
                continue;
            }
            for (JsonNode affect : vuln.path("affects")) {
                String ref = affect.path("ref").asText(null);
                if (ref != null) {
                    vulnsByRef.computeIfAbsent(ref, k -> new ArrayList<>()).add(cve);
                }
            }
        }

        List<Artifact> artifacts = new ArrayList<>();
        int idx = 0;
        for (JsonNode c : components) {
            idx++;
            String name = c.path("name").asText(null);
            String version = c.path("version").asText(null);
            if (name == null || name.isBlank()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "CycloneDX: component #" + idx + " missing name");
            }
            if (version == null || version.isBlank()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "CycloneDX: component '" + name + "' missing version");
            }
            String purl = c.path("purl").asText(null);
            String bomRef = c.path("bom-ref").asText(purl);
            String license = null;
            JsonNode licenses = c.path("licenses");
            if (licenses.isArray() && !licenses.isEmpty()) {
                JsonNode first = licenses.get(0);
                license = first.path("license").path("id").asText(null);
                if (license == null) {
                    license = first.path("license").path("name").asText(null);
                }
                if (license == null) {
                    license = first.path("expression").asText(null);
                }
            }
            String hash = null;
            for (JsonNode h : c.path("hashes")) {
                if ("SHA-256".equalsIgnoreCase(h.path("alg").asText())) {
                    hash = h.path("content").asText(null);
                    break;
                }
            }
            String supplier = c.path("supplier").path("name").asText(null);
            List<String> vulns = vulnsByRef.getOrDefault(bomRef, List.of());
            artifacts.add(new Artifact(name, version, purl, license, List.copyOf(vulns), supplier, hash));
        }
        return List.copyOf(artifacts);
    }
}
