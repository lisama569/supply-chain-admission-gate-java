package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.List;

/**
 * 归一化后的组件。
 *
 * @param name            组件名
 * @param version         版本
 * @param license         许可证标识（可为空）
 * @param vulnerabilities 命中的漏洞
 */
public record Component(String name,
                        String version,
                        String license,
                        List<Vulnerability> vulnerabilities) {
    public Component {
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
    }
}
