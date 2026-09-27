package com.github.lisama569.supplychainadmissiongatejava.common;

/**
 * 本地模拟的操作者上下文。
 *
 * @param username 用户名
 * @param role     角色
 */
public record UserContext(String username, Role role) {
}
