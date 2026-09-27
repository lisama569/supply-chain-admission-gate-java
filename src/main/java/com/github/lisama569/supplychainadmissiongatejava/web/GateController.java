package com.github.lisama569.supplychainadmissiongatejava.web;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.common.Role;
import com.github.lisama569.supplychainadmissiongatejava.common.UserContext;
import com.github.lisama569.supplychainadmissiongatejava.gate.GateService;
import com.github.lisama569.supplychainadmissiongatejava.importing.ImportService;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionStatus;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 本地准入门面的最小 REST 接口。角色通过 X-User / X-Role 请求头模拟。 */
@RestController
@RequestMapping("/api/gate")
public class GateController {

    private final ImportService importService;
    private final GateService gateService;
    private final PolicyService policyService;

    public GateController(ImportService importService,
                          GateService gateService,
                          PolicyService policyService) {
        this.importService = importService;
        this.gateService = gateService;
        this.policyService = policyService;
    }

    public record ImportRequest(String requestId, String format,
                                String manifestBase64, String signatureHex) {
    }

    public record ProvenanceRequest(String requestId,
                                    String provenanceBase64, String signatureHex) {
    }

    public record PolicyPublishRequest(String requestId,
                                       long expectedVersion,
                                       String blockSeverity,
                                       List<String> blockedLicenses,
                                       boolean blockCopyleft,
                                       int requiredSlsaLevel,
                                       boolean requireVerifiedBuilder,
                                       List<String> trustedBuilders,
                                       String note) {
    }

    public record ActionRequest(String requestId, String reason, String targetStatus) {
    }

    @PostMapping("/artifacts/imports")
    public ArtifactRecord importManifest(@RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
                                         @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
                                         @RequestBody ImportRequest request) {
        requireText(request.requestId(), "requestId");
        requireText(request.format(), "format");
        requireText(request.manifestBase64(), "manifestBase64");
        byte[] bytes = decodeBase64(request.manifestBase64());
        return importService.importManifest(user(user, role), request.requestId(),
                request.format(), bytes, request.signatureHex());
    }

    @PostMapping("/artifacts/{key}/provenance")
    public ArtifactRecord attachProvenance(@RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
                                           @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
                                           @PathVariable String key,
                                           @RequestBody ProvenanceRequest request) {
        requireText(request.requestId(), "requestId");
        requireText(request.provenanceBase64(), "provenanceBase64");
        return importService.attachProvenance(user(user, role), request.requestId(), key,
                decodeBase64(request.provenanceBase64()), request.signatureHex());
    }

    @PostMapping("/artifacts/{key}/decisions")
    public DecisionRecord decide(@RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
                                 @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
                                 @PathVariable String key,
                                 @RequestBody ActionRequest request) {
        requireText(request.requestId(), "requestId");
        return gateService.decide(user(user, role), request.requestId(), key);
    }

    @PostMapping("/artifacts/{key}/quarantine")
    public DecisionRecord quarantine(@RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
                                     @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
                                     @PathVariable String key,
                                     @RequestBody ActionRequest request) {
        requireText(request.requestId(), "requestId");
        return gateService.quarantine(user(user, role), request.requestId(), key, request.reason());
    }

    @PostMapping("/artifacts/{key}/override")
    public DecisionRecord override(@RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
                                   @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
                                   @PathVariable String key,
                                   @RequestBody ActionRequest request) {
        requireText(request.requestId(), "requestId");
        requireText(request.targetStatus(), "targetStatus");
        DecisionStatus target;
        try {
            target = DecisionStatus.valueOf(request.targetStatus().trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "未知目标状态: " + request.targetStatus());
        }
        return gateService.override(user(user, role), request.requestId(), key, target, request.reason());
    }

    @GetMapping("/decisions/{id}")
    public DecisionRecord getDecision(@PathVariable String id) {
        return gateService.getDecision(id);
    }

    @GetMapping("/artifacts/{key}/decisions")
    public List<DecisionRecord> history(@PathVariable String key) {
        return gateService.history(key);
    }

    @GetMapping("/policies/current")
    public Policy currentPolicy() {
        return policyService.current();
    }

    @GetMapping("/policies")
    public List<Policy> policyHistory() {
        return policyService.history();
    }

    @GetMapping("/policies/v{version}")
    public Policy policyVersion(@PathVariable long version) {
        return policyService.getVersion(version);
    }

    @PostMapping("/policies")
    public ResponseEntity<Policy> publishPolicy(
            @RequestHeader(value = "X-User", defaultValue = "anonymous") String user,
            @RequestHeader(value = "X-Role", defaultValue = "guest") String role,
            @RequestBody PolicyPublishRequest request) {
        requireText(request.requestId(), "requestId");
        Severity severity;
        try {
            severity = Severity.valueOf(request.blockSeverity().trim().toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "未知或缺失 blockSeverity: " + request.blockSeverity());
        }
        Policy published = policyService.publish(user(user, role), request.requestId(),
                request.expectedVersion(),
                new PolicyService.Draft(severity,
                        request.blockedLicenses() == null ? List.of() : request.blockedLicenses(),
                        request.blockCopyleft(), request.requiredSlsaLevel(),
                        request.requireVerifiedBuilder(),
                        request.trustedBuilders() == null ? List.of() : request.trustedBuilders(),
                        request.note()));
        return ResponseEntity.status(HttpStatus.CREATED).body(published);
    }

    static UserContext user(String user, String roleHeader) {
        return new UserContext(user == null || user.isBlank() ? "anonymous" : user,
                Role.fromName(roleHeader));
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new GateException(RejectionReason.MISSING_FIELD, "缺少字段: " + field);
        }
    }

    private static byte[] decodeBase64(String base64) {
        try {
            return Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new GateException(RejectionReason.MALFORMED_DOCUMENT,
                    "Base64 内容非法: " + e.getMessage());
        }
    }
}
