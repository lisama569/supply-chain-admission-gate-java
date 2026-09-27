package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.List;

/**
 * 多格式清单归一化后的统一视图。
 *
 * @param format           原始格式：spdx / cyclonedx / internal
 * @param formatVersion    原始格式版本
 * @param artifactName     制品名
 * @param artifactVersion  制品版本
 * @param artifactDigest   制品摘要（十六进制）
 * @param digestAlg        摘要算法
 * @param supplier         供应商标识
 * @param components       组件列表
 * @param licenses         许可证列表
 * @param declaredVulns    清单中直接声明的漏洞
 */
public record NormalizedManifest(String format,
                                 String formatVersion,
                                 String artifactName,
                                 String artifactVersion,
                                 String artifactDigest,
                                 String digestAlg,
                                 String supplier,
                                 List<Component> components,
                                 List<License> licenses,
                                 List<Vulnerability> declaredVulns) {
    public NormalizedManifest {
        components = components == null ? List.of() : List.copyOf(components);
        licenses = licenses == null ? List.of() : List.copyOf(licenses);
        declaredVulns = declaredVulns == null ? List.of() : List.copyOf(declaredVulns);
    }
}
