package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;
import com.github.lisama569.supplychainadmissiongatejava.model.Severity;
import com.github.lisama569.supplychainadmissiongatejava.policy.PolicyService;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 幂等与并发测试：
 * - 重复提交返回同一结果；同幂等键不同请求体必须拒绝；
 * - 策略并发发布串行化、版本号连续单调，恰好一个成功，其余版本冲突；
 * - 并发发布期间的所有判定，读到的策略版本只能是某个完整版本，无混合结果。
 */
class IdempotencyAndConcurrencyTest {

    private GateTestFixtures fx;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        fx = new GateTestFixtures(tempDir);
    }

    @Test
    void duplicateImportIsIdempotentAndSameObjectPersisted() {
        byte[] body = GateTestFixtures.sample("valid", "cyclonedx-1.5.json");
        String sig = GateTestFixtures.signature("valid", "cyclonedx-1.5.json");

        ArtifactRecord first = fx.importService.importManifest(GateTestFixtures.analyst(),
                "idem-import-1", "cyclonedx", body, sig);
        ArtifactRecord second = fx.importService.importManifest(GateTestFixtures.analyst(),
                "idem-import-1", "cyclonedx", body, sig);
        assertEquals(first.artifactKey(), second.artifactKey());
        assertEquals(first.digestHex(), second.digestHex());
        assertEquals(first.importRequestId(), second.importRequestId());
        assertEquals(1, fx.artifacts.findAll().size(), "重复提交不得产生第二条制品记录");
        System.out.println("[幂等] 重复导入返回同一制品 key=" + second.artifactKey());
    }

    @Test
    void sameIdempotencyKeyWithDifferentBodyIsRejected() {
        byte[] body = GateTestFixtures.sample("valid", "cyclonedx-1.5.json");
        fx.importService.importManifest(GateTestFixtures.analyst(),
                "idem-conflict-1", "cyclonedx", body,
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "idem-conflict-1", "cyclonedx",
                        GateTestFixtures.sample("valid", "manifest-v1.json"),
                        GateTestFixtures.signature("valid", "manifest-v1.json")));
        assertEquals(RejectionReason.DUPLICATE_CONFLICT, ex.reason());
    }

    @Test
    void duplicateDecisionIsIdempotent() {
        ArtifactRecord artifact = fx.importService.importManifest(GateTestFixtures.analyst(),
                "idem-dec-art", "cyclonedx",
                GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
        DecisionRecord first = fx.gateService.decide(GateTestFixtures.approver(),
                "idem-dec-1", artifact.artifactKey());
        DecisionRecord second = fx.gateService.decide(GateTestFixtures.approver(),
                "idem-dec-1", artifact.artifactKey());
        assertEquals(first.decisionId(), second.decisionId());
        assertEquals(first.rationale(), second.rationale());
        assertEquals(1, fx.decisions.findByArtifact(artifact.artifactKey()).size(),
                "重复判定不得产生新记录");
    }

    @Test
    void duplicatePolicyPublishIsIdempotent() {
        PolicyService.Draft draft = draft(Severity.HIGH, "重复发布测试");
        Policy first = fx.policyService.publish(GateTestFixtures.policyAdmin(),
                "idem-pub-1", 0, draft);
        Policy second = fx.policyService.publish(GateTestFixtures.policyAdmin(),
                "idem-pub-1", 0, draft);
        assertEquals(first.version(), second.version());
        assertEquals(1, fx.policyService.history().size());
        System.out.println("[幂等] 重复发布返回同一策略版本 v" + second.version());
    }

    @Test
    void concurrentPolicyPublishesSerializeWithExactlyOneWinner() throws Exception {
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Long> publishedVersions = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<RejectionReason> rejections = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new java.util.ArrayList<>();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    Policy published = fx.policyService.publish(GateTestFixtures.policyAdmin(),
                            "concurrent-pub-" + idx, 0,
                            draft(Severity.HIGH, "并发发布 #" + idx));
                    publishedVersions.add(published.version());
                } catch (GateException e) {
                    rejections.add(e.reason());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        assertEquals(1, publishedVersions.size(), "恰好一个发布成功");
        assertEquals(1L, publishedVersions.iterator().next());
        assertEquals(threads - 1, rejections.size(), "其余全部版本冲突");
        assertTrue(rejections.stream().allMatch(r -> r == RejectionReason.POLICY_VERSION_CONFLICT),
                "所有失败都必须是 POLICY_VERSION_CONFLICT，实际: " + rejections);

        List<Policy> history = fx.policyService.history();
        assertEquals(List.of(1L), history.stream().map(Policy::version).toList(),
                "版本号必须连续单调，无重复版本文件");
        System.out.println("[并发] 12 个并发发布：1 成功(v1)，11 版本冲突，历史="
                + history.stream().map(p -> "v" + p.version()).toList());
    }

    @Test
    void decisionsDuringConcurrentPublishingNeverSeeMixedVersions() throws Exception {
        // 先导入一个“始终干净”的制品（cyclonedx + 可信来源 L3）
        ArtifactRecord artifact = fx.importService.importManifest(GateTestFixtures.analyst(),
                "mix-art", "cyclonedx",
                GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
        fx.importService.attachProvenance(GateTestFixtures.analyst(), "mix-prov",
                artifact.artifactKey(),
                GateTestFixtures.sample("valid", "provenance-cyclonedx-v1.json"),
                GateTestFixtures.signature("valid", "provenance-cyclonedx-v1.json"));

        int publishers = 6;
        int decisionMakers = 6;
        ExecutorService pool = Executors.newFixedThreadPool(publishers + decisionMakers);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Long> seenVersions = new ConcurrentLinkedQueue<>();
        AtomicInteger conflicts = new AtomicInteger();
        List<Future<?>> futures = new java.util.ArrayList<>();

        for (int i = 0; i < publishers; i++) {
            // 所有发布者都基于同一个“看到的”基线 v0 竞争：恰好一个成功，其余 409
            final int idx = i;
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    fx.policyService.publish(GateTestFixtures.policyAdmin(),
                            "mix-pub-" + idx, 0,
                            draft(idx % 2 == 0 ? Severity.HIGH : Severity.CRITICAL,
                                    "混合并发 #" + idx));
                } catch (GateException e) {
                    if (e.reason() == RejectionReason.POLICY_VERSION_CONFLICT) {
                        conflicts.incrementAndGet();
                    } else {
                        throw new RuntimeException(e);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        for (int i = 0; i < decisionMakers; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    DecisionRecord d = fx.gateService.decide(GateTestFixtures.approver(),
                            "mix-dec-" + idx, artifact.artifactKey());
                    seenVersions.add(d.policyVersion());
                    // 每个判定必须能在历史中找到完整的对应版本
                    Policy snapshot = fx.policyService.getVersion(d.policyVersion());
                    assertEquals(d.policyVersion(), snapshot.version());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(15, TimeUnit.SECONDS);
        }
        pool.shutdown();

        System.out.println("[并发] 判定观察到的策略版本集合=" + seenVersions.stream().sorted().distinct().toList()
                + "，发布冲突数=" + conflicts.get());
        long finalVersion = fx.policyService.current().version();
        assertEquals(1, finalVersion, "6 个发布者基线各异，仅基线 v0 的请求能成功一次");
        assertTrue(seenVersions.stream().allMatch(v -> v == 0 || v == 1),
                "判定只可能读到发布前 v0 或发布后 v1，绝不允许中间/混合版本");
        assertNotEquals(0, seenVersions.size());
    }

    private static PolicyService.Draft draft(Severity severity, String note) {
        return new PolicyService.Draft(severity,
                List.of("AGPL-3.0-only", "AGPL-3.0-or-later"),
                true, 2, true,
                List.of("pkg:generic/trusted-builder@v1"), note);
    }
}
