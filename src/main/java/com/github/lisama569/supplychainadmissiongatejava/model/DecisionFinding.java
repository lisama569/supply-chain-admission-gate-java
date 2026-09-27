package com.github.lisama569.supplychainadmissiongatejava.model;

/**
 * 单条判定依据。
 *
 * @param riskType 风险维度
 * @param severity 严重等级（许可/来源风险用触发阈值表示）
 * @param ruleId   命中的策略规则
 * @param detail   人类可读说明
 */
public record DecisionFinding(RiskType riskType,
                              Severity severity,
                              String ruleId,
                              String detail) {
}
