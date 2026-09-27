package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * REST 端到端测试：通过 X-User/X-Role 头模拟角色，验证状态码与拒绝原因体。
 * 使用独立数据目录与样本密钥（gate.data-dir / gate.signing-key-path 由测试 properties 注入）。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiTest {

    @org.springframework.test.context.DynamicPropertySource
    static void dataDir(org.springframework.test.context.DynamicPropertyRegistry registry) {
        registry.add("gate.data-dir", () -> DATA_DIR.toString());
        registry.add("gate.signing-key-path", () -> Path.of("samples/keys/hmac.key").toString());
    }

    static final Path DATA_DIR = createTempDir();

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("gate-web-test-");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;

    private static String validCdxB64;
    private static String validCdxSig;

    @BeforeAll
    static void loadSamples() throws Exception {
        Path samples = Path.of("samples/valid");
        validCdxB64 = Base64.getEncoder().encodeToString(
                Files.readAllBytes(samples.resolve("cyclonedx-1.5.json")));
        validCdxSig = Files.readString(samples.resolve("cyclonedx-1.5.json.sig"),
                StandardCharsets.UTF_8).trim();
    }

    @Test
    void importDecideAndQueryHappyPath() throws Exception {
        String body = mapper.writeValueAsString(new ImportBody("web-req-1",
                "cyclonedx", validCdxB64, validCdxSig));
        mockMvc.perform(post("/api/gate/artifacts/imports")
                        .header("X-User", "alice").header("X-Role", "analyst")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.artifactKey").value("edge-gateway@7.0.1"));

        // 无来源 -> 自动判定会隔离（PROV-MISSING），但需要 APPROVER
        String decide = mapper.writeValueAsString(new ActionBody("web-dec-1", null, null));
        mockMvc.perform(post("/api/gate/artifacts/edge-gateway@7.0.1/decisions")
                        .header("X-User", "bob").header("X-Role", "approver")
                        .contentType(MediaType.APPLICATION_JSON).content(decide))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("QUARANTINED"))
                .andExpect(jsonPath("$.policyVersion").value(0));

        mockMvc.perform(get("/api/gate/decisions/dec-web-dec-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findings[0].ruleId").value("PROV-MISSING"));
    }

    @Test
    void invalidSignatureReturns400WithDistinguishableReason() throws Exception {
        String body = mapper.writeValueAsString(new ImportBody("web-bad-sig",
                "cyclonedx", validCdxB64, "0".repeat(64)));
        mockMvc.perform(post("/api/gate/artifacts/imports")
                        .header("X-User", "alice").header("X-Role", "analyst")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_SIGNATURE"));
    }

    @Test
    void forbiddenRoleReturns403() throws Exception {
        String body = mapper.writeValueAsString(new ImportBody("web-403",
                "cyclonedx", validCdxB64, validCdxSig));
        mockMvc.perform(post("/api/gate/artifacts/imports")
                        .header("X-User", "erin").header("X-Role", "guest")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FORBIDDEN"));
    }

    @Test
    void concurrentPolicyPublishOverHttpYieldsOne201AndRest409() throws Exception {
        // 串行发送两个基于同一过期基线 v0 的不同发布：第一个 201，第二个 409
        String p1 = publishBody("web-pub-1", 0, "HIGH");
        mockMvc.perform(post("/api/gate/policies")
                        .header("X-User", "carol").header("X-Role", "policy_admin")
                        .contentType(MediaType.APPLICATION_JSON).content(p1))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.version").value(1));

        String p2 = publishBody("web-pub-2", 0, "CRITICAL");
        mockMvc.perform(post("/api/gate/policies")
                        .header("X-User", "carol").header("X-Role", "policy_admin")
                        .contentType(MediaType.APPLICATION_JSON).content(p2))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("POLICY_VERSION_CONFLICT"));

        mockMvc.perform(get("/api/gate/policies/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1));
    }

    private String publishBody(String requestId, long expectedVersion, String severity)
            throws Exception {
        var node = mapper.createObjectNode();
        node.put("requestId", requestId);
        node.put("expectedVersion", expectedVersion);
        node.put("blockSeverity", severity);
        node.put("blockCopyleft", true);
        node.put("requiredSlsaLevel", 2);
        node.put("requireVerifiedBuilder", true);
        node.putPOJO("blockedLicenses", java.util.List.of("AGPL-3.0-only"));
        node.putPOJO("trustedBuilders", java.util.List.of("pkg:generic/trusted-builder@v1"));
        node.put("note", "web 并发测试");
        return mapper.writeValueAsString(node);
    }

    record ImportBody(String requestId, String format, String manifestBase64, String signatureHex) {
    }

    record ActionBody(String requestId, String reason, String targetStatus) {
    }
}
