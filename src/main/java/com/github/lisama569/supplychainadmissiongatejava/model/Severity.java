package com.github.lisama569.supplychainadmissiongatejava.model;

/** 漏洞严重等级，顺序即风险优先级。 */
public enum Severity {
    NONE, LOW, MEDIUM, HIGH, CRITICAL;

    /** 按 CVSS v3.1 常用分段映射为本地严重等级。 */
    public static Severity fromCvss(double score) {
        if (score >= 9.0) {
            return CRITICAL;
        }
        if (score >= 7.0) {
            return HIGH;
        }
        if (score >= 4.0) {
            return MEDIUM;
        }
        if (score > 0.0) {
            return LOW;
        }
        return NONE;
    }
}
