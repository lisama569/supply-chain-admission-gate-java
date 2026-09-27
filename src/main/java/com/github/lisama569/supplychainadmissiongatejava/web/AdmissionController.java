package com.github.lisama569.supplychainadmissiongatejava.web;

import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.Role;
import com.github.lisama569.supplychainadmissiongatejava.policy.Policy;
import com.github.lisama569.supplychainadmissiongatejava.service.AdmissionGateService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;

/** REST entry points for admission, policy publish, override and audit. */
@RestController
@RequestMapping("/api/gate")
public class AdmissionController {

    private final AdmissionGateService service;

    public AdmissionController(AdmissionGateService service) {
        this.service = service;
    }

    public record SubmitRequest(String manifest, String provenance,
                                String idempotencyKey, String actor) {
    }

    public record PolicyRequest(int maxVulnerabilities, Set<String> bannedLicenses,
                                Set<String> trustedIssuers, String actor) {
    }

    public record OverrideRequest(String actor, String justification) {
    }

    @PostMapping("/submit")
    public DecisionRecord submit(@RequestBody SubmitRequest request,
                                 @RequestHeader("X-Role") Role role) {
        return service.submit(request.manifest(), request.provenance(),
                request.idempotencyKey(), role, request.actor());
    }

    @PostMapping("/policy")
    public Policy publishPolicy(@RequestBody PolicyRequest request,
                                @RequestHeader("X-Role") Role role) {
        return service.publishPolicy(new Policy(0L, request.maxVulnerabilities(),
                request.bannedLicenses(), request.trustedIssuers()), role, request.actor());
    }

    @GetMapping("/policy")
    public Policy currentPolicy() {
        return service.currentPolicy();
    }

    @PostMapping("/decisions/{decisionId}/override")
    public DecisionRecord override(@PathVariable String decisionId,
                                   @RequestBody OverrideRequest request,
                                   @RequestHeader("X-Role") Role role) {
        return service.override(decisionId, role, request.actor(), request.justification());
    }

    @GetMapping("/decisions")
    public List<DecisionRecord> history() {
        return service.history();
    }

    @GetMapping("/decisions/{decisionId}")
    public DecisionRecord decision(@PathVariable String decisionId) {
        return service.findDecision(decisionId)
                .orElseThrow(() -> new IllegalArgumentException("no decision " + decisionId));
    }
}
