package com.github.lisama569.supplychainadmissiongatejava.service;

import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;

/** Raised when a role attempts an operation it is not allowed to perform. */
public class PermissionDeniedException extends RuntimeException {
    private final RejectReason reason = RejectReason.PERMISSION_DENIED;

    public PermissionDeniedException(String message) {
        super(message);
    }

    public RejectReason reason() {
        return reason;
    }
}
