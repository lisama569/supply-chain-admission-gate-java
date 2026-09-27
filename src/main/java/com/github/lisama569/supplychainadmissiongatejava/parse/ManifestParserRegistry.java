package com.github.lisama569.supplychainadmissiongatejava.parse;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** 按格式标识选择解析器；未知格式必须报 UNSUPPORTED_FORMAT，不允许走默认分支静默通过。 */
@Component
public class ManifestParserRegistry {

    private final Map<String, ManifestParser> parsers = new LinkedHashMap<>();

    public ManifestParserRegistry(List<ManifestParser> parserList) {
        for (ManifestParser parser : parserList) {
            parsers.put(parser.format(), parser);
        }
    }

    public ManifestParser require(String format) {
        if (format == null || format.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少格式标识 format");
        }
        ManifestParser parser = parsers.get(format.trim().toLowerCase());
        if (parser == null) {
            throw new GateException(RejectionReason.UNSUPPORTED_FORMAT,
                    "不支持的清单格式: " + format + "，支持的格式: " + parsers.keySet());
        }
        return parser;
    }
}
