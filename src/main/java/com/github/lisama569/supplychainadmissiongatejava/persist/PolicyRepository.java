package com.github.lisama569.supplychainadmissiongatejava.persist;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.Policy;

/**
 * 策略版本仓储。
 *
 * <p>存储布局：{@code policies/v<版本>.json} 为不可变版本文件，
 * {@code policies/current.json} 为当前版本指针。发布时先落版本文件，
 * 再原子切换指针，全过程在单实例内加锁：读者要么看到旧版本、要么看到新版本，
 * 不会看到混合版本。</p>
 */
public class PolicyRepository {

    static final String COLLECTION = "policies";
    private static final String CURRENT_KEY = "current";

    /** 当前版本指针。 */
    public record CurrentPointer(long version) {
    }

    private final JsonStore store;

    public PolicyRepository() {
        this(new JsonStore(java.nio.file.Path.of("./target/gate-data")));
    }

    public PolicyRepository(JsonStore store) {
        this.store = store;
    }

    /** 读取当前生效版本；无已发布版本时返回内置默认策略 v0。 */
    public synchronized Policy current() {
        CurrentPointer pointer = store.read(COLLECTION, CURRENT_KEY, CurrentPointer.class);
        if (pointer == null) {
            return Policy.defaultPolicy();
        }
        Policy policy = store.read(COLLECTION, versionKey(pointer.version()), Policy.class);
        if (policy == null) {
            // 指针与版本文件不一致属于存储损坏，绝不静默回退
            throw new GateException(RejectionReason.ILLEGAL_STATE,
                    "当前策略指针指向不存在的版本 v" + pointer.version());
        }
        return policy;
    }

    public synchronized Optional<Policy> findVersion(long version) {
        if (version <= 0) {
            return Optional.of(Policy.defaultPolicy());
        }
        return Optional.ofNullable(store.read(COLLECTION, versionKey(version), Policy.class));
    }

    public synchronized List<Policy> history() {
        // 只读取 v<版本>.json，排除 current.json 指针文件
        return store.keys(COLLECTION).stream()
                .filter(k -> k.startsWith("v"))
                .map(k -> store.read(COLLECTION, k, Policy.class))
                .sorted(Comparator.comparingLong(Policy::version))
                .toList();
    }

    /**
     * 乐观并发控制：仅当当前版本 == expectedCurrentVersion 时发布 next。
     * 重复提交同一版本内容（相同 expectedVersion 且新版本号相同）将命中幂等逻辑（在服务层处理），
     * 真正的版本竞争抛 {@link RejectionReason#POLICY_VERSION_CONFLICT}。
     */
    public synchronized Policy publishIfCurrent(long expectedCurrentVersion, Policy next) {
        Policy current = current();
        if (current.version() != expectedCurrentVersion) {
            throw new GateException(RejectionReason.POLICY_VERSION_CONFLICT,
                    "策略版本冲突：期望基线 v" + expectedCurrentVersion
                            + "，实际当前为 v" + current.version());
        }
        long nextVersion = current.version() + 1;
        if (next.version() != nextVersion) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "新版本号必须为 " + nextVersion + "，实际为 v" + next.version());
        }
        // 先落不可变版本文件，再切指针：切换瞬间原子可见完整版本
        store.writeAtomic(COLLECTION, versionKey(nextVersion), next);
        store.writeAtomic(COLLECTION, CURRENT_KEY, new CurrentPointer(nextVersion));
        return next;
    }

    private static String versionKey(long version) {
        return "v" + version;
    }
}
