package com.github.lisama569.supplychainadmissiongatejava.persist;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;

/**
 * 判定记录仓储。
 * 每次判定产生一个不可变记录文件（键为 decisionId），追加式保存，重启后可追溯。
 */
public class DecisionRepository {

    static final String COLLECTION = "decisions";

    private final JsonStore store;

    public DecisionRepository() {
        this(new JsonStore(java.nio.file.Path.of("./target/gate-data")));
    }

    public DecisionRepository(JsonStore store) {
        this.store = store;
    }

    public synchronized Optional<DecisionRecord> find(String decisionId) {
        return Optional.ofNullable(store.read(COLLECTION, decisionId, DecisionRecord.class));
    }

    /** 同一制品的最新判定：按决策时间（再按 decisionId 兜底）排序。 */
    public synchronized Optional<DecisionRecord> latestForArtifact(String artifactKey) {
        return findByArtifact(artifactKey).stream().max(COMPARATOR);
    }

    public synchronized DecisionRecord save(DecisionRecord record) {
        store.writeAtomic(COLLECTION, record.decisionId(), record);
        return record;
    }

    public synchronized List<DecisionRecord> findByArtifact(String artifactKey) {
        return store.readAll(COLLECTION, DecisionRecord.class).stream()
                .filter(d -> d.artifactKey().equals(artifactKey))
                .sorted(COMPARATOR)
                .toList();
    }

    public synchronized List<DecisionRecord> findAll() {
        return store.readAll(COLLECTION, DecisionRecord.class).stream()
                .sorted(COMPARATOR)
                .toList();
    }

    private static final Comparator<DecisionRecord> COMPARATOR =
            Comparator.comparingLong(DecisionRecord::decidedAt)
                    .thenComparing(DecisionRecord::decisionId);
}
