package com.github.lisama569.supplychainadmissiongatejava.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.supplychainadmissiongatejava.model.NormalizedManifest;

/**
 * 清单解析器：把某种外部格式的 JSON 归一化为 {@link NormalizedManifest}。
 */
public interface ManifestParser {

    /** 支持的格式标识。 */
    String format();

    /** 归一化；任何字段缺失/版本不兼容都必须抛出可区分的 GateException。 */
    NormalizedManifest parse(JsonNode root);
}
