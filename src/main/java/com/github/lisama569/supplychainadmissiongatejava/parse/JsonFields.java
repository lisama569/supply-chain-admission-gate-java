package com.github.lisama569.supplychainadmissiongatejava.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;

/** 解析期的字段读取工具：缺失/类型错误一律抛可区分异常，绝不返回 null 静默通过。 */
final class JsonFields {

    private JsonFields() {
    }

    static JsonNode requireObject(JsonNode parent, String field) {
        if (parent == null || !parent.has(field) || parent.get(field).isNull()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少必填字段: " + field);
        }
        JsonNode node = parent.get(field);
        if (!node.isObject()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "字段类型错误（期望对象）: " + field);
        }
        return node;
    }

    static String requireText(JsonNode parent, String field) {
        if (parent == null || !parent.has(field) || parent.get(field).isNull()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少必填字段: " + field);
        }
        JsonNode node = parent.get(field);
        if (!node.isTextual() || node.asText().isBlank()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "字段缺失或非非空字符串: " + field);
        }
        return node.asText();
    }

    static String optionalText(JsonNode parent, String field) {
        if (parent == null || !parent.hasNonNull(field)) {
            return null;
        }
        JsonNode node = parent.get(field);
        return node.isTextual() ? node.asText() : null;
    }

    static void requireVersion(JsonNode root, String field, String expected, String supportedHint) {
        String actual = requireText(root, field);
        if (!expected.equals(actual)) {
            throw new GateException(RejectionReason.INCOMPATIBLE_VERSION,
                    "不兼容的格式版本: " + field + "=" + actual
                            + "，仅支持 " + supportedHint);
        }
    }

    static int requireInt(JsonNode parent, String field) {
        if (parent == null || !parent.hasNonNull(field)) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少必填字段: " + field);
        }
        JsonNode node = parent.get(field);
        if (!node.isNumber()) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "字段类型错误（期望数字）: " + field);
        }
        return node.asInt();
    }
}
