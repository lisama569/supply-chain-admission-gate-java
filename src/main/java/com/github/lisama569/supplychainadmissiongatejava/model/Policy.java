package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.List;

/**
 * 准入策略（带版本号的不可变值对象）。
 *
 * @param version             单调递增版本号，从 1 开始
 * @param blockSeverity       漏洞风险：达到该严重等级即隔离
 * @param blockedLicenses     明确禁止的许可证标识
 * @param blockCopyleft       是否禁止强 Copyleft 许可证
 * @param requiredSlsaLevel   最低可信 SLSA 等级
 * @param requireVerifiedBuilder 是否要求可信构建者
 * @param trustedBuilders     可信构建者标识列表
 * @param publishedAt         发布时间（毫秒）
 * @param publishedBy         发布者
 * @param note                备注
 */
public record Policy(long version,
                     Severity blockSeverity,
                     List<String> blockedLicenses,
                     boolean blockCopyleft,
                     int requiredSlsaLevel,
                     boolean requireVerifiedBuilder,
                     List<String> trustedBuilders,
                     long publishedAt,
                     String publishedBy,
                     String note) {

    public Policy {
        blockedLicenses = blockedLicenses == null ? List.of() : List.copyOf(blockedLicenses);
        trustedBuilders = trustedBuilders == null ? List.of() : List.copyOf(trustedBuilders);
    }

    public static Policy defaultPolicy() {
        return new Policy(0, Severity.HIGH, List.of("AGPL-3.0-only", "AGPL-3.0-or-later"),
                true, 2, true, List.of("pkg:generic/trusted-builder@v1"),
                0L, "system", "内置默认策略（未发布的版本 0）");
    }
}
