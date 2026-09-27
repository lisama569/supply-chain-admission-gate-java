package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;

/** Raised when input material cannot be accepted; always carries a distinguishable reason. */
public class IngestException extends RuntimeException {
    private final RejectReason reason;

    public IngestException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectReason reason() {
        return reason;
    }
}
