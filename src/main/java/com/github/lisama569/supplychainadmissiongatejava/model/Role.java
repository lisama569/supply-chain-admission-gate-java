package com.github.lisama569.supplychainadmissiongatejava.model;

import java.util.EnumSet;
import java.util.Set;

/** Roles and the operations each may perform. */
public enum Role {
    ADMISSION_OPERATOR,
    QUARANTINE_OPERATOR,
    POLICY_ADMIN,
    OVERRIDE_ADMIN;

    public Set<Operation> operations() {
        return switch (this) {
            case ADMISSION_OPERATOR -> EnumSet.of(Operation.ADMIT, Operation.IMPORT);
            case QUARANTINE_OPERATOR -> EnumSet.of(Operation.QUARANTINE, Operation.IMPORT);
            case POLICY_ADMIN -> EnumSet.of(Operation.POLICY_PUBLISH);
            case OVERRIDE_ADMIN -> EnumSet.of(Operation.OVERRIDE, Operation.IMPORT);
        };
    }

    public boolean allows(Operation op) {
        return operations().contains(op);
    }

    public enum Operation {
        IMPORT, ADMIT, QUARANTINE, POLICY_PUBLISH, OVERRIDE
    }
}
