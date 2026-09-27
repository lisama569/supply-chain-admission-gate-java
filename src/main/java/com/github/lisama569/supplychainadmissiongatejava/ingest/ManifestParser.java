package com.github.lisama569.supplychainadmissiongatejava.ingest;

import com.github.lisama569.supplychainadmissiongatejava.model.Artifact;
import com.github.lisama569.supplychainadmissiongatejava.model.ManifestFormat;

import java.util.List;

/** Parses one manifest format into normalized artifacts. */
public interface ManifestParser {
    ManifestFormat format();

    boolean supports(String content);

    List<Artifact> parse(String content);
}
