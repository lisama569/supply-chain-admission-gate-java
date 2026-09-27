package com.github.lisama569.supplychainadmissiongatejava.persist;

import java.time.Instant;
import java.util.Optional;

/**
 * 幂等键存储：记录请求键 -> 结果引用 + 请求体哈希。
 * 方法在单实例内加锁，保证“检查-写入”原子完成，重复/并发请求不会各写一份。
 */
public class IdempotencyRepository {

    static final String COLLECTION = "idempotency";

    /** 幂等条目。 */
    public record Entry(String requestId,
                        String requestHash,
                        String resultRef,
                        Instant createdAt) {
    }

    private final JsonStore store;

    public IdempotencyRepository() {
        this(new JsonStore(java.nio.file.Path.of("./target/gate-data")));
    }

    public IdempotencyRepository(JsonStore store) {
        this.store = store;
    }

    public synchronized Optional<Entry> find(String requestId) {
        return Optional.ofNullable(store.read(COLLECTION, requestId, Entry.class));
    }

    /** 首次写入；若键已存在返回已有条目（由调用方据此保持幂等或报 DUPLICATE_CONFLICT）。 */
    public synchronized Entry saveIfAbsent(Entry entry) {
        Entry existing = store.read(COLLECTION, entry.requestId(), Entry.class);
        if (existing != null) {
            return existing;
        }
        store.writeAtomic(COLLECTION, entry.requestId(), entry);
        return entry;
    }

    public synchronized void updateResult(String requestId, String resultRef) {
        Entry existing = store.read(COLLECTION, requestId, Entry.class);
        if (existing == null) {
            throw new IllegalStateException("幂等条目不存在: " + requestId);
        }
        store.writeAtomic(COLLECTION, requestId,
                new Entry(existing.requestId(), existing.requestHash(), resultRef, existing.createdAt()));
    }
}
