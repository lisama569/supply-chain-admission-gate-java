package com.github.lisama569.supplychainadmissiongatejava.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 本地样本签名工具：对材料原始字节做 HMAC-SHA256。
 * 仅用于工作区内模拟，不代表真实供应链签名体系。
 */
public class HmacSigner {

    private static final String ALG = "HmacSHA256";

    private final byte[] key;

    public HmacSigner() {
        this(new byte[0]);
    }

    public HmacSigner(byte[] key) {
        this.key = key == null ? new byte[0] : key.clone();
    }

    public byte[] sign(byte[] payload) {
        try {
            Mac mac = newMac(key);
            return mac.doFinal(payload == null ? new byte[0] : payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    /** 常量时间比较，避免有效签名被时序侧信道区分。 */
    public boolean verify(byte[] payload, byte[] expectedMac) {
        if (expectedMac == null || expectedMac.length == 0) {
            return false;
        }
        byte[] actual = sign(payload);
        return MessageDigestEquals.matches(actual, expectedMac);
    }

    public boolean verifyHex(byte[] payload, String expectedHex) {
        if (expectedHex == null || expectedHex.isBlank()) {
            return false;
        }
        try {
            return verify(payload, decodeHex(expectedHex.trim()));
        } catch (IllegalArgumentException malformedHex) {
            return false;
        }
    }

    public static byte[] decodeHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex 为 null");
        }
        String h = hex.trim();
        if (h.length() % 2 != 0) {
            throw new IllegalArgumentException("十六进制长度必须为偶数: " + hex);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(h.charAt(i * 2), 16);
            int low = Character.digit(h.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("非法十六进制字符: " + hex);
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    public static String encodeHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] utf8(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    public static Mac newMac(byte[] key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(ALG);
        mac.init(new SecretKeySpec(key == null ? new byte[0] : key, ALG));
        return mac;
    }

    /** 常量时间比较（长度不等时也尽量做等长比较后再返回）。 */
    private static final class MessageDigestEquals {
        static boolean matches(byte[] a, byte[] b) {
            if (a.length != b.length) {
                // 长度不同必然不匹配；先做一次完整异或保持耗时稳定
                int dummy = 0;
                for (int i = 0; i < a.length; i++) {
                    dummy |= a[i] ^ (i < b.length ? b[i] : 0);
                }
                return false;
            }
            return Arrays.equals(a, b);
        }
    }
}
