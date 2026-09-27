package com.github.lisama569.supplychainadmissiongatejava.common;

/**
 * 领域异常：携带可区分的拒绝原因与可读细节。
 */
public class GateException extends RuntimeException {

    private final RejectionReason reason;

    public GateException(RejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public GateException(RejectionReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public RejectionReason reason() {
        return reason;
    }
}
