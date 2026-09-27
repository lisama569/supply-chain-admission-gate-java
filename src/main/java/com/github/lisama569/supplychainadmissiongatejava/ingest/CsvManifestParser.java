package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;
import com.github.lisama569.supplychainadmissiongatejava.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple CSV manifest. Required header:
 * name,version,purl,license,vulnerabilities,supplier,sha256
 * 'vulnerabilities' is a ';' separated list (may be empty).
 */
@Component
public class CsvManifestParser implements ManifestParser {

    static final String EXPECTED_HEADER = "name,version,purl,license,vulnerabilities,supplier,sha256";

    @Override
    public ManifestFormat format() {
        return ManifestFormat.CSV;
    }

    @Override
    public boolean supports(String content) {
        if (content == null) {
            return false;
        }
        String first = content.lines().findFirst().orElse("").trim();
        return first.equals(EXPECTED_HEADER);
    }

    @Override
    public List<Artifact> parse(String content) {
        List<String> lines = content.lines().filter(l -> !l.isBlank()).toList();
        if (lines.isEmpty() || !lines.get(0).trim().equals(EXPECTED_HEADER)) {
            throw new IngestException(RejectReason.MALFORMED_INPUT,
                    "CSV: header must be exactly: " + EXPECTED_HEADER);
        }
        if (lines.size() < 2) {
            throw new IngestException(RejectReason.MISSING_FIELD, "CSV: no artifact rows");
        }
        List<Artifact> artifacts = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String[] cols = lines.get(i).split(",", -1);
            if (cols.length != 7) {
                throw new IngestException(RejectReason.MALFORMED_INPUT,
                        "CSV: row " + (i + 1) + " has " + cols.length + " columns, expected 7");
            }
            String name = cols[0].trim();
            String version = cols[1].trim();
            if (name.isEmpty()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "CSV: row " + (i + 1) + " missing name");
            }
            if (version.isEmpty()) {
                throw new IngestException(RejectReason.MISSING_FIELD,
                        "CSV: row " + (i + 1) + " ('" + name + "') missing version");
            }
            List<String> vulns = cols[4].isBlank()
                    ? List.of()
                    : List.of(cols[4].trim().split(";"));
            artifacts.add(new Artifact(
                    name, version,
                    blankToNull(cols[2]), blankToNull(cols[3]),
                    vulns, blankToNull(cols[5]), blankToNull(cols[6])));
        }
        return List.copyOf(artifacts);
    }

    private static String blankToNull(String s) {
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
