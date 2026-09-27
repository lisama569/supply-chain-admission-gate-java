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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 内部简单格式 manifest-v1 解析器：
 * <pre>
 * {
 *   "manifestVersion": 1,
 *   "artifact": {"name","version","supplier","digestAlg","digest"},
 *   "components": [{"name","version","license","vulnerabilities":[{"id","severity","cvss"}]}],
 *   "licenses": ["Apache-2.0"]
 * }
 * </pre>
 */
@org.springframework.stereotype.Component
public class InternalManifestParser implements ManifestParser {

    private static final int VERSION = 1;

    @Override
    public String format() {
        return "internal";
    }

    @Override
    public NormalizedManifest parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "清单根节点必须为对象");
        }
        int version = JsonFields.requireInt(root, "manifestVersion");
        if (version != VERSION) {
            throw new GateException(RejectionReason.INCOMPATIBLE_VERSION,
                    "不兼容的清单版本 manifestVersion=" + version + "，仅支持 1");
        }
        JsonNode artifact = JsonFields.requireObject(root, "artifact");
        String name = JsonFields.requireText(artifact, "name");
        String artifactVersion = JsonFields.requireText(artifact, "version");
        String alg = JsonFields.requireText(artifact, "digestAlg");
        if (!"SHA-256".equalsIgnoreCase(alg)) {
            throw new GateException(RejectionReason.UNSUPPORTED_ALGORITHM,
                    "不支持的摘要算法: " + alg + "，仅支持 SHA-256");
        }
        String digest = JsonFields.requireText(artifact, "digest").trim().toLowerCase();
        if (!digest.matches("[0-9a-f]{64}")) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "SHA-256 摘要格式非法（应为 64 位十六进制）");
        }
        String supplier = JsonFields.optionalText(artifact, "supplier");

        List<Component> components = new ArrayList<>();
        Set<String> licenseIds = new LinkedHashSet<>();
        JsonNode componentArray = root.get("components");
        if (componentArray != null) {
            if (!componentArray.isArray()) {
                throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "components 必须为数组");
            }
            for (JsonNode comp : componentArray) {
                String cName = JsonFields.requireText(comp, "name");
                String cVersion = JsonFields.requireText(comp, "version");
                String cLicense = JsonFields.optionalText(comp, "license");
                if (cLicense != null) {
                    licenseIds.add(cLicense);
                }
                components.add(new Component(cName, cVersion, cLicense, parseVulns(comp.get("vulnerabilities"))));
            }
        }

        JsonNode topLicenses = root.get("licenses");
        if (topLicenses != null) {
            if (!topLicenses.isArray()) {
                throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "licenses 必须为数组");
            }
            for (JsonNode license : topLicenses) {
                if (!license.isTextual() || license.asText().isBlank()) {
                    throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "licenses 条目必须为非空字符串");
                }
                licenseIds.add(license.asText());
            }
        }

        List<License> licenses = new ArrayList<>();
        for (String id : licenseIds) {
            licenses.add(new License(id, LicenseRules.isCopyleft(id)));
        }

        return new NormalizedManifest(format(), String.valueOf(VERSION), name, artifactVersion,
                digest, "SHA-256", supplier, components, licenses, List.of());
    }

    private static List<Vulnerability> parseVulns(JsonNode array) {
        List<Vulnerability> result = new ArrayList<>();
        if (array == null) {
            return result;
        }
        if (!array.isArray()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT, "vulnerabilities 必须为数组");
        }
        for (JsonNode vuln : array) {
            String id = JsonFields.requireText(vuln, "id");
            Double cvss = vuln.hasNonNull("cvss") && vuln.get("cvss").isNumber()
                    ? vuln.get("cvss").asDouble() : null;
            Severity severity;
            if (vuln.hasNonNull("severity") && vuln.get("severity").isTextual()) {
                try {
                    severity = Severity.valueOf(vuln.get("severity").asText().trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                            "未知的漏洞严重等级: " + vuln.get("severity").asText());
                }
            } else if (cvss != null) {
                severity = Severity.fromCvss(cvss);
            } else {
                severity = Severity.MEDIUM;
            }
            result.add(new Vulnerability(id, severity, cvss));
        }
        return result;
    }
}
