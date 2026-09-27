package com.github.lisama569.supplychainadmissiongatejava.tests;

import com.github.lisama569.supplychainadmissiongatejava.ingest.CsvManifestParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.CycloneDxParser;
import com.github.lisama569.supplychainadmissiongatejava.ingest.IngestException;
import com.github.lisama569.supplychainadmissiongatejava.ingest.ManifestIngestor;
import com.github.lisama569.supplychainadmissiongatejava.ingest.SpdxParser;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ManifestIngestorTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestIngestorTest.class);
    private static final Path SAMPLES = Path.of("samples");

    private final ManifestIngestor ingestor = new ManifestIngestor(
            List.of(new CycloneDxParser(), new SpdxParser(), new CsvManifestParser()));

    private static String sample(String name) throws IOException {
        return Files.readString(SAMPLES.resolve(name));
    }

    @Test
    void importsCycloneDx() throws IOException {
        var result = ingestor.ingest(sample("manifest-cyclonedx.json"));
        log.info("input=cyclonedx format={} artifacts={}", result.format(), result.artifacts());
        assertEquals(ManifestFormat.CYCLONEDX_JSON, result.format());
        assertEquals(2, result.artifacts().size());
        var legacy = result.artifacts().get(1);
        assertEquals("legacy-lib", legacy.name());
        assertEquals(List.of("CVE-2026-0001", "CVE-2026-0002"), legacy.vulnerabilities());
        assertEquals("GPL-3.0-only", legacy.license());
    }

    @Test
    void importsSpdx() throws IOException {
        var result = ingestor.ingest(sample("manifest-spdx.json"));
        log.info("input=spdx format={} artifacts={}", result.format(), result.artifacts());
        assertEquals(ManifestFormat.SPDX_JSON, result.format());
        assertEquals(2, result.artifacts().size());
        assertEquals("widget-core", result.artifacts().get(0).name());
        assertEquals("Acme Corp", result.artifacts().get(0).supplier());
        assertEquals("pkg:maven/com.acme/widget-core@2.1.0", result.artifacts().get(0).purl());
    }

    @Test
    void importsCsv() throws IOException {
        var result = ingestor.ingest(sample("manifest.csv"));
        log.info("input=csv format={} artifacts={}", result.format(), result.artifacts());
        assertEquals(ManifestFormat.CSV, result.format());
        assertEquals(2, result.artifacts().size());
        assertEquals(List.of("CVE-2026-1001", "CVE-2026-1002"),
                result.artifacts().get(1).vulnerabilities());
    }

    @Test
    void rejectsMissingField() throws IOException {
        IngestException e = assertThrows(IngestException.class,
                () -> ingestor.ingest(sample("manifest-missing-field.json")));
        log.info("input=missing-field reason={} message={}", e.reason(), e.getMessage());
        assertEquals(RejectReason.MISSING_FIELD, e.reason());
    }

    @Test
    void rejectsUnsupportedFormatVersion() throws IOException {
        IngestException e = assertThrows(IngestException.class,
                () -> ingestor.ingest(sample("manifest-bad-version.json")));
        log.info("input=bad-version reason={} message={}", e.reason(), e.getMessage());
        assertEquals(RejectReason.UNSUPPORTED_FORMAT_VERSION, e.reason());
    }

    @Test
    void rejectsUnrecognizedFormat() {
        IngestException e = assertThrows(IngestException.class,
                () -> ingestor.ingest("<xml>not a supported manifest</xml>"));
        log.info("input=unrecognized reason={} message={}", e.reason(), e.getMessage());
        assertEquals(RejectReason.MALFORMED_INPUT, e.reason());
    }

    @Test
    void rejectsEmptyInput() {
        IngestException e = assertThrows(IngestException.class, () -> ingestor.ingest("  "));
        assertEquals(RejectReason.MALFORMED_INPUT, e.reason());
    }
}
