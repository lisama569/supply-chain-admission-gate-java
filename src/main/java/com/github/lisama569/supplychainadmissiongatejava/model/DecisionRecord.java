package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.List;

/**
 * 一次准入判定的完整记录（审计依据，重启后仍可追溯）。
 *
 * @param decisionId      判定幂等键
 * @param artifactKey     制品标识
 * @param artifactDigest  判定时制品摘要
 * @param status          最终结论
 * @param policyVersion   判定所用策略版本
 * @param findings        全部命中依据（即使最终被更高优先级风险覆盖也保留）
 * @param rationale       人类可读的确定性解释
 * @param decidedAt       判定时间（毫秒）
 * @param decidedBy       触发者
 * @param overriddenBy    覆盖者（仅 OVERRIDDEN）
 * @param overrideReason  覆盖原因
 */
public record DecisionRecord(String decisionId,
                             String artifactKey,
                             String artifactDigest,
                             DecisionStatus status,
                             long policyVersion,
                             List<DecisionFinding> findings,
                             String rationale,
                             long decidedAt,
                             String decidedBy,
                             String overriddenBy,
                             String overrideReason) {

    public DecisionRecord {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}
