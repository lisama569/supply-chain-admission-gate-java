package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.List;

/** Detects format, delegates to the matching parser, normalizes results. */
@Component
public class ManifestIngestor {

    private final List<ManifestParser> parsers;

    public ManifestIngestor(List<ManifestParser> parsers) {
        this.parsers = List.copyOf(parsers);
    }

    public record IngestResult(ManifestFormat format, List<Artifact> artifacts) {
    }

    public IngestResult ingest(String content) {
        if (content == null || content.isBlank()) {
            throw new IngestException(RejectReason.MALFORMED_INPUT, "empty manifest content");
        }
        for (ManifestParser parser : parsers) {
            if (parser.supports(content)) {
                List<Artifact> artifacts = parser.parse(content);
                return new IngestResult(parser.format(), artifacts);
            }
        }
        throw new IngestException(RejectReason.MALFORMED_INPUT,
                "unrecognized manifest format (supported: CycloneDX JSON, SPDX JSON, CSV)");
    }
}
