package com.github.lisama569.supplychainadmissiongatejava.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.supplychainadmissiongatejava.ingest.IngestException;
import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ProvenanceInfo;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Parses provenance JSON: {"issuer":..., "repository":..., "signature":...,
 * "signedPayload":..., "declaredSupplier":...}.
 * Detects contradictions between provenance and manifest content.
 */
@Component
public class ProvenanceParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public record ParsedProvenance(ProvenanceInfo info, String declaredSupplier) {
    }

    public ParsedProvenance parse(String provenanceJson) {
        if (provenanceJson == null || provenanceJson.isBlank()) {
            throw new IngestException(RejectReason.MISSING_FIELD, "provenance material is required");
        }
        final JsonNode root;
        try {
            root = MAPPER.readTree(provenanceJson);
        } catch (Exception e) {
            throw new IngestException(RejectReason.MALFORMED_INPUT, "provenance: invalid JSON");
        }
        String issuer = text(root, "issuer");
        String signature = text(root, "signature");
        String signedPayload = text(root, "signedPayload");
        if (issuer == null) {
            throw new IngestException(RejectReason.MISSING_FIELD, "provenance: missing issuer");
        }
        if (signature == null) {
            throw new IngestException(RejectReason.MISSING_FIELD, "provenance: missing signature");
        }
        if (signedPayload == null) {
            throw new IngestException(RejectReason.MISSING_FIELD, "provenance: missing signedPayload");
        }
        return new ParsedProvenance(
                new ProvenanceInfo(issuer, text(root, "repository"), signature, signedPayload),
                text(root, "declaredSupplier"));
    }

    /** Rejects when provenance and manifest contradict each other. */
    public void checkConsistency(ParsedProvenance provenance, List<Artifact> artifacts) {
        if (provenance.declaredSupplier() == null) {
            return;
        }
        for (Artifact a : artifacts) {
            if (a.supplier() != null && !a.supplier().equals(provenance.declaredSupplier())) {
                throw new IngestException(RejectReason.PROVENANCE_CONFLICT,
                        "provenance declares supplier '" + provenance.declaredSupplier()
                                + "' but artifact '" + a.name() + "' declares '" + a.supplier() + "'");
            }
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() && !v.asText().isBlank() ? v.asText() : null;
    }
}
