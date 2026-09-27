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
 * SPDX 2.3 JSON 格式解析器（本地模拟子集）。
 * 文档名对应的 package 视为制品本体，其余 package 为组件。
 */
@org.springframework.stereotype.Component
public class SpdxManifestParser implements ManifestParser {

    private static final String VERSION = "SPDX-2.3";

    @Override
    public String format() {
        return "spdx";
    }

    @Override
    public NormalizedManifest parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "SPDX 文档根节点必须为对象");
        }
        JsonFields.requireVersion(root, "spdxVersion", VERSION, VERSION);
        String docName = JsonFields.requireText(root, "name");

        JsonNode packages = root.get("packages");
        if (packages == null || !packages.isArray() || packages.isEmpty()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "SPDX 文档缺少非空 packages 数组");
        }

        JsonNode rootPackage = null;
        List<JsonNode> componentPackages = new ArrayList<>();
        for (JsonNode pkg : packages) {
            String name = JsonFields.requireText(pkg, "name");
            if (rootPackage == null && name.equals(docName)) {
                rootPackage = pkg;
            } else {
                componentPackages.add(pkg);
            }
        }
        if (rootPackage == null) {
            rootPackage = packages.get(0); // 兜底：第一个包视为制品本体
        }

        String artifactVersion = JsonFields.requireText(rootPackage, "versionInfo");
        String supplier = JsonFields.optionalText(rootPackage, "supplier");
        String digest = extractSha256(rootPackage);
        String rootLicense = JsonFields.optionalText(rootPackage, "licenseDeclared");

        List<Vulnerability> declared = parseVulnerabilities(root.get("vulnerabilities"));
        Map<String, List<Vulnerability>> byComponent = mapByComponent(declared, root.get("vulnerabilities"));

        List<Component> components = new ArrayList<>();
        Set<String> licenseIds = new LinkedHashSet<>();
        if (rootLicense != null) {
            licenseIds.add(rootLicense);
        }
        for (JsonNode pkg : componentPackages) {
            String name = JsonFields.requireText(pkg, "name");
            String version = JsonFields.requireText(pkg, "versionInfo");
            String license = JsonFields.optionalText(pkg, "licenseDeclared");
            if (license != null) {
                licenseIds.add(license);
            }
            components.add(new Component(name, version, license,
                    byComponent.getOrDefault(name, List.of())));
        }

        List<License> licenses = new ArrayList<>();
        for (String id : licenseIds) {
            licenses.add(new License(id, LicenseRules.isCopyleft(id)));
        }

        return new NormalizedManifest(format(), VERSION, docName, artifactVersion,
                digest, "SHA-256", supplier, components, licenses, declared);
    }

    private static String extractSha256(JsonNode pkg) {
        JsonNode checksums = pkg.get("checksums");
        if (checksums == null || !checksums.isArray() || checksums.isEmpty()) {
            throw new GateException(RejectionReason.MISSING_FIELD,
                    "制品包缺少 checksums: " + JsonFields.optionalText(pkg, "name"));
        }
        for (JsonNode checksum : checksums) {
            String algorithm = JsonFields.requireText(checksum, "algorithm");
            if ("SHA256".equalsIgnoreCase(algorithm) || "SHA-256".equalsIgnoreCase(algorithm)) {
                String value = JsonFields.requireText(checksum, "checksumValue").trim().toLowerCase();
                if (value.length() != 64 || !value.matches("[0-9a-f]{64}")) {
                    throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                            "SHA-256 摘要格式非法（应为 64 位十六进制）");
                }
                return value;
            }
            if (algorithm.toUpperCase().startsWith("MD") || algorithm.toUpperCase().startsWith("SHA1")) {
                throw new GateException(RejectionReason.UNSUPPORTED_ALGORITHM,
                        "不支持的摘要算法: " + algorithm + "，仅支持 SHA-256");
            }
        }
        throw new GateException(RejectionReason.MISSING_FIELD, "缺少 SHA-256 checksum");
    }

    private static List<Vulnerability> parseVulnerabilities(JsonNode array) {
        List<Vulnerability> result = new ArrayList<>();
        if (array == null) {
            return result;
        }
        if (!array.isArray()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "vulnerabilities 必须为数组");
        }
        for (JsonNode vuln : array) {
            String id = JsonFields.requireText(vuln, "id");
            Severity severity;
            if (vuln.hasNonNull("severity") && vuln.get("severity").isTextual()) {
                try {
                    severity = Severity.valueOf(vuln.get("severity").asText().trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                            "未知的漏洞严重等级: " + vuln.get("severity").asText());
                }
            } else if (vuln.hasNonNull("cvss") && vuln.get("cvss").isNumber()) {
                severity = Severity.fromCvss(vuln.get("cvss").asDouble());
            } else {
                // 无评分的漏洞按保守默认 MEDIUM 处理，不会被静默忽略
                severity = Severity.MEDIUM;
            }
            Double cvss = vuln.hasNonNull("cvss") && vuln.get("cvss").isNumber()
                    ? vuln.get("cvss").asDouble() : null;
            result.add(new Vulnerability(id, severity, cvss));
        }
        return result;
    }

    private static Map<String, List<Vulnerability>> mapByComponent(List<Vulnerability> vulns,
                                                                   JsonNode raw) {
        Map<String, List<Vulnerability>> map = new LinkedHashMap<>();
        if (raw == null) {
            return map;
        }
        int i = 0;
        for (JsonNode vuln : raw) {
            String affected = JsonFields.optionalText(vuln, "affected");
            if (affected != null) {
                map.computeIfAbsent(affected, k -> new ArrayList<>()).add(vulns.get(i));
            }
            i++;
        }
        return map;
    }
}
