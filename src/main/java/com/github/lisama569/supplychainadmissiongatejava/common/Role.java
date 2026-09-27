package com.github.lisama569.supplychainadmissiongatejava.common;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** 角色及其权限边界。 */
public enum Role {
    GUEST(EnumSet.noneOf(Permission.class)),
    ANALYST(EnumSet.of(Permission.IMPORT_MATERIAL)),
    APPROVER(EnumSet.of(Permission.IMPORT_MATERIAL,
            Permission.ADMIT_ARTIFACT,
            Permission.QUARANTINE_ARTIFACT)),
    POLICY_ADMIN(EnumSet.of(Permission.PUBLISH_POLICY)),
    SECURITY_OFFICER(EnumSet.of(Permission.IMPORT_MATERIAL,
            Permission.ADMIT_ARTIFACT,
            Permission.QUARANTINE_ARTIFACT,
            Permission.PUBLISH_POLICY,
            Permission.OVERRIDE_DECISION));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = EnumSet.copyOf(permissions);
    }

    public boolean permits(Permission permission) {
        return permissions.contains(permission);
    }

    public Set<Permission> permissions() {
        return EnumSet.copyOf(permissions);
    }

    static final Map<String, Role> BY_NAME = Map.of(
            "guest", GUEST,
            "analyst", ANALYST,
            "approver", APPROVER,
            "policy_admin", POLICY_ADMIN,
            "policy-admin", POLICY_ADMIN,
            "security_officer", SECURITY_OFFICER,
            "security-officer", SECURITY_OFFICER);

    /**
     * 解析角色名（大小写/连字符不敏感）；无法识别时返回 GUEST（无权限），绝不提权。
     */
    public static Role fromName(String name) {
        if (name == null || name.isBlank()) {
            return GUEST;
        }
        Role role = BY_NAME.get(name.trim().toLowerCase());
        return role == null ? GUEST : role;
    }
}
