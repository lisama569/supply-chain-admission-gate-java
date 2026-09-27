package com.github.lisama569.supplychainadmissiongatejava.persist;

import java.util.List;
import java.util.Optional;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;

/** 制品档案仓储：导入形成的快照按制品键持久化。 */
public class ArtifactRepository {

    static final String COLLECTION = "artifacts";

    private final JsonStore store;

    public ArtifactRepository() {
        this(new JsonStore(java.nio.file.Path.of("./target/gate-data")));
    }

    public ArtifactRepository(JsonStore store) {
        this.store = store;
    }

    public synchronized Optional<ArtifactRecord> find(String artifactKey) {
        return Optional.ofNullable(store.read(COLLECTION, artifactKey, ArtifactRecord.class));
    }

    public synchronized ArtifactRecord save(ArtifactRecord record) {
        store.writeAtomic(COLLECTION, record.artifactKey(), record);
        return record;
    }

    public synchronized List<ArtifactRecord> findAll() {
        return store.readAll(COLLECTION, ArtifactRecord.class);
    }
}
