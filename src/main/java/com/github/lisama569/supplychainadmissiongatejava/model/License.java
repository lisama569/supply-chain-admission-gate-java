package com.github.lisama569.supplychainadmissiongatejava.model;

/**
 * 许可证条目。
 *
 * @param id     SPDX 许可证标识，如 Apache-2.0
 * @param copyleft 是否为强 Copyleft（策略判定的本地简化标记）
 */
public record License(String id, boolean copyleft) {
}
