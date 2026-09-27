package com.github.lisama569.supplychainadmissiongatejava.provenance;

import com.github.lisama569.supplychainadmissiongatejava.model.ProvenanceInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Verifies provenance signatures locally. Each trusted issuer has an HMAC key
 * configured via {@code gate.issuer-keys.<issuer>=<secret>}. Signature is the
 * lowercase hex of HMAC-SHA256(key, signedPayload).
 */
@Component
public class SignatureVerifier {

    private final Map<String, String> issuerKeys;

    public SignatureVerifier(@Value("${gate.issuer-keys:}") String issuerKeysConfig) {
        Map<String, String> keys = new LinkedHashMap<>();
        if (issuerKeysConfig != null && !issuerKeysConfig.isBlank()) {
            for (String pair : issuerKeysConfig.split(",")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2 && !kv[0].isBlank()) {
                    keys.put(kv[0].trim(), kv[1].trim());
                }
            }
        }
        this.issuerKeys = Map.copyOf(keys);
    }

    public boolean hasIssuer(String issuer) {
        return issuer != null && issuerKeys.containsKey(issuer);
    }

    public boolean verify(ProvenanceInfo provenance) {
        if (provenance == null || provenance.issuer() == null
                || provenance.signature() == null || provenance.signedPayload() == null) {
            return false;
        }
        String key = issuerKeys.get(provenance.issuer());
        if (key == null) {
            return false;
        }
        String expected = hmacSha256Hex(key, provenance.signedPayload());
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provenance.signature().toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    public static String hmacSha256Hex(String key, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] raw = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}
