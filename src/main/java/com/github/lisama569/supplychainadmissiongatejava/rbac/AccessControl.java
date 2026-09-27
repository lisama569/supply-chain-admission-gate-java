package com.github.lisama569.supplychainadmissiongatejava.rbac;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.Permission;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.common.Role;
import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import org.springframework.stereotype.Component;

/**
 * 基于角色的权限校验。权限边界：
 * <ul>
 *   <li>GUEST：无任何写权限</li>
 *   <li>ANALYST：仅导入材料</li>
 *   <li>APPROVER：导入、准入判定、人工隔离</li>
 *   <li>POLICY_ADMIN：仅发布策略</li>
 *   <li>SECURITY_OFFICER：全部操作，含安全覆盖</li>
 * </ul>
 */
@Component
public class AccessControl {

    public void require(UserContext user, Permission permission) {
        if (user == null || user.role() == null) {
            throw new GateException(RejectionReason.FORBIDDEN,
                    "缺少操作者上下文，拒绝执行 " + permission);
        }
        if (!user.role().permits(permission)) {
            throw new GateException(RejectionReason.FORBIDDEN,
                    "角色 " + user.role() + "（用户 " + user.username()
                            + "）无权执行 " + permission);
        }
    }

    public boolean can(Role role, Permission permission) {
        return role != null && role.permits(permission);
    }
}
