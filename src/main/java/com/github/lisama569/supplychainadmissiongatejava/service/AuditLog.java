package com.github.lisama569.supplychainadmissiongatejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.supplychainadmissiongatejava.model.DecisionRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Append-only JSON-lines log of decision records. Loaded into memory at
 * startup, so history survives restarts and stays queryable. All mutating
 * operations are synchronized; readers see a consistent snapshot.
 */
@Component
public class AuditLog {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final Path file;
    private final Map<String, DecisionRecord> byIdempotencyKey = new LinkedHashMap<>();
    private final Map<String, DecisionRecord> byId = new LinkedHashMap<>();

    public AuditLog(@Value("${gate.audit-file:data/audit.log}") String auditFile) {
        this.file = Path.of(auditFile);
        load();
    }

    private synchronized void load() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file)) {
                if (line.isBlank()) {
                    continue;
                }
                DecisionRecord record = MAPPER.readValue(line, DecisionRecord.class);
                byIdempotencyKey.put(record.idempotencyKey(), record);
                byId.put(record.decisionId(), record);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load audit log " + file, e);
        }
    }

    public synchronized void append(DecisionRecord record) {
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            String line = MAPPER.writeValueAsString(record) + System.lineSeparator();
            Files.writeString(file, line,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            byIdempotencyKey.put(record.idempotencyKey(), record);
            byId.put(record.decisionId(), record);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to append audit log", e);
        }
    }

    public synchronized Optional<DecisionRecord> findByIdempotencyKey(String key) {
        return Optional.ofNullable(byIdempotencyKey.get(key));
    }

    public synchronized Optional<DecisionRecord> findById(String decisionId) {
        return Optional.ofNullable(byId.get(decisionId));
    }

    public synchronized List<DecisionRecord> all() {
        return new ArrayList<>(byId.values());
    }
}
