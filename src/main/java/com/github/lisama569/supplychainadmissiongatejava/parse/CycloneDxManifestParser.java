package com.github.lisama569.supplychainadmissiongatejava.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Component;
import com.github.lisama569.supplychainadmissiongatejava.model.License;
import com.github.lisama569.supplychainadmissiongatejava.model.NormalizedManifest;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.model.Vulnerability;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CycloneDX 1.5 JSON 格式解析器（本地模拟子集）。
 * metadata.component 为制品本体，components 为依赖组件。
 */
@org.springframework.stereotype.Component
public class CycloneDxManifestParser implements ManifestParser {

    private static final String VERSION = "1.5";

    @Override
    public String format() {
        return "cyclonedx";
    }

    @Override
    public NormalizedManifest parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "CycloneDX 文档根节点必须为对象");
        }
        JsonFields.requireVersion(root, "specVersion", VERSION, VERSION);

        JsonNode metadata = JsonFields.requireObject(root, "metadata");
        JsonNode rootComponent = JsonFields.requireObject(metadata, "component");
        String artifactName = JsonFields.requireText(rootComponent, "name");
        String artifactVersion = JsonFields.requireText(rootComponent, "version");
        String digest = extractSha256(rootComponent);
        String supplier = extractSupplier(rootComponent);
        String rootLicense = extractLicenseId(rootComponent);

        JsonNode rawVulns = root.get("vulnerabilities");
        List<VulnRef> refs = parseVulnerabilities(rawVulns);
        Map<String, List<Vulnerability>> byComponent = new LinkedHashMap<>();
        List<Vulnerability> declared = new ArrayList<>();
        for (VulnRef ref : refs) {
            declared.add(ref.vulnerability());
            if (ref.affected() != null) {
                byComponent.computeIfAbsent(ref.affected(), k -> new ArrayList<>()).add(ref.vulnerability());
            }
        }

        List<Component> components = new ArrayList<>();
        Set<String> licenseIds = new LinkedHashSet<>();
        if (rootLicense != null) {
            licenseIds.add(rootLicense);
        }
        JsonNode componentArray = root.get("components");
        if (componentArray != null) {
            if (!componentArray.isArray()) {
                throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "components 必须为数组");
            }
            for (JsonNode comp : componentArray) {
                String name = JsonFields.requireText(comp, "name");
                String version = JsonFields.requireText(comp, "version");
                String license = extractLicenseId(comp);
                if (license != null) {
                    licenseIds.add(license);
                }
                components.add(new Component(name, version, license,
                        byComponent.getOrDefault(name, List.of())));
            }
        }

        List<License> licenses = new ArrayList<>();
        for (String id : licenseIds) {
            licenses.add(new License(id, LicenseRules.isCopyleft(id)));
        }

        return new NormalizedManifest(format(), VERSION, artifactName, artifactVersion,
                digest, "SHA-256", supplier, components, licenses, declared);
    }

    private static String extractSha256(JsonNode component) {
        JsonNode hashes = component.get("hashes");
        if (hashes == null || !hashes.isArray() || hashes.isEmpty()) {
            throw new GateException(RejectionReason.MISSING_FIELD,
                    "制品缺少 hashes: " + JsonFields.optionalText(component, "name"));
        }
        for (JsonNode hash : hashes) {
            String algorithm = JsonFields.requireText(hash, "alg");
            if ("SHA-256".equalsIgnoreCase(algorithm)) {
                String value = JsonFields.requireText(hash, "content").trim().toLowerCase();
                if (!value.matches("[0-9a-f]{64}")) {
                    throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                            "SHA-256 摘要格式非法（应为 64 位十六进制）");
                }
                return value;
            }
        }
        throw new GateException(RejectionReason.MISSING_FIELD, "缺少 alg=SHA-256 的 hash");
    }

    private static String extractSupplier(JsonNode component) {
        if (!component.hasNonNull("supplier")) {
            return null;
        }
        JsonNode supplier = component.get("supplier");
        if (supplier.isObject()) {
            return JsonFields.optionalText(supplier, "name");
        }
        return supplier.isTextual() ? supplier.asText() : null;
    }

    private static String extractLicenseId(JsonNode component) {
        JsonNode licenses = component.get("licenses");
        if (licenses == null || !licenses.isArray() || licenses.isEmpty()) {
            return null;
        }
        JsonNode first = licenses.get(0);
        if (first.hasNonNull("license") && first.get("license").isObject()) {
            return JsonFields.optionalText(first.get("license"), "id");
        }
        return JsonFields.optionalText(first, "expression");
    }

    private record VulnRef(Vulnerability vulnerability, String affected) {
    }

    private static List<VulnRef> parseVulnerabilities(JsonNode array) {
        List<VulnRef> refs = new ArrayList<>();
        if (array == null) {
            return refs;
        }
        if (!array.isArray()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "vulnerabilities 必须为数组");
        }
        for (JsonNode vuln : array) {
            String id = JsonFields.requireText(vuln, "id");
            String affected = null;
            JsonNode affects = vuln.get("affects");
            if (affects != null && affects.isArray() && !affects.isEmpty()) {
                JsonNode target = affects.get(0).get("ref");
                if (target != null && target.isTextual()) {
                    String ref = target.asText();
                    // purl 形如 pkg:maven/group/name@version，取 name 部分
                    int at = ref.indexOf('@');
                    String beforeVersion = at >= 0 ? ref.substring(0, at) : ref;
                    int slash = beforeVersion.lastIndexOf('/');
                    affected = slash >= 0 ? beforeVersion.substring(slash + 1) : beforeVersion;
                }
            }
            Severity severity = Severity.MEDIUM;
            Double cvss = null;
            JsonNode ratings = vuln.get("ratings");
            if (ratings != null && ratings.isArray() && !ratings.isEmpty()) {
                JsonNode rating = ratings.get(0);
                if (rating.hasNonNull("severity") && rating.get("severity").isTextual()) {
                    try {
                        String name = rating.get("severity").asText().trim();
                        severity = Severity.valueOf(name.equalsIgnoreCase("none") ? "NONE" : name.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        severity = Severity.MEDIUM;
                    }
                }
                JsonNode score = rating.get("score");
                if (score != null && score.isNumber()) {
                    cvss = score.asDouble();
                    if (!(rating.hasNonNull("severity"))) {
                        severity = Severity.fromCvss(cvss);
                    }
                }
            }
            refs.add(new VulnRef(new Vulnerability(id, severity, cvss), affected));
        }
        return refs;
    }
}
