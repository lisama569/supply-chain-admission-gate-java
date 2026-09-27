package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 并发导入：同一请求体 + 同一幂等键并发提交，只允许产生一条制品记录，所有调用结果一致。 */
class ConcurrentImportTest {

    @Test
    void parallelImportsWithSameIdempotencyKeyCreateExactlyOneArtifact(
            @TempDir Path tempDir) throws Exception {
        GateTestFixtures fx = new GateTestFixtures(tempDir);
        byte[] body = GateTestFixtures.sample("valid", "spdx-2.3.json");
        String sig = GateTestFixtures.signature("valid", "spdx-2.3.json");

        int n = 10;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<ArtifactRecord>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return fx.importService.importManifest(GateTestFixtures.analyst(),
                        "parallel-same-key", "spdx", body, sig);
            }));
        }
        start.countDown();
        List<String> keys = new ArrayList<>();
        for (Future<ArtifactRecord> f : futures) {
            keys.add(f.get(10, TimeUnit.SECONDS).artifactKey());
        }
        pool.shutdown();

        assertEquals(n, keys.size());
        assertEquals(1, keys.stream().distinct().count(), "所有并发调用必须返回同一制品");
        assertEquals(1, fx.artifacts.findAll().size(), "只允许落一条制品记录，无半更新重复");
        System.out.println("[并发导入] " + n + " 个并发同键请求 -> 单一制品 " + keys.get(0));
    }
}
