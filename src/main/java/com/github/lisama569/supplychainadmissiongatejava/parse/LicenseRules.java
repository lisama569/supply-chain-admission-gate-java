package com.github.lisama569.supplychainadmissiongatejava.parse;

import java.util.Set;

/**
 * 本地许可证规则：已知的强/弱 Copyleft 许可证集合。
 * 仅用于样本判定的简化分类，真实系统应接入完整 SPDX 许可证矩阵。
 */
public final class LicenseRules {

    private static final Set<String> COPYLEFT = Set.of(
            "GPL-1.0-only", "GPL-1.0-or-later",
            "GPL-2.0-only", "GPL-2.0-or-later",
            "GPL-3.0-only", "GPL-3.0-or-later",
            "AGPL-1.0-only", "AGPL-1.0-or-later",
            "AGPL-3.0-only", "AGPL-3.0-or-later",
            "LGPL-2.0-only", "LGPL-2.0-or-later",
            "LGPL-2.1-only", "LGPL-2.1-or-later",
            "LGPL-3.0-only", "LGPL-3.0-or-later");

    private LicenseRules() {
    }

    public static boolean isCopyleft(String licenseId) {
        return licenseId != null && COPYLEFT.contains(licenseId.trim());
    }
}
