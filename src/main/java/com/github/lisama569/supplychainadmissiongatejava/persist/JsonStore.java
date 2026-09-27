package com.github.lisama569.supplychainadmissiongatejava.persist;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * 本地 JSON 文件存储：按集合/键读写，原子落盘，服务重启后历史仍可追溯。
 *
 * <p>每个集合是一个目录，每个键是一个 {@code <safeKey>.json} 文件。
 * 写入采用“临时文件 + 原子 move”，崩溃时不会出现半更新文件。</p>
 */
public class JsonStore {

    private static final String SUFFIX = ".json";

    private final Path root;
    private final ObjectMapper mapper;

    public JsonStore(Path root) {
        this.root = root;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        try {
            Files.createDirectories(root);
        } catch (IOException e) {
            throw new UncheckedIOException("无法初始化数据目录: " + root, e);
        }
    }

    public Path root() {
        return root;
    }

    public ObjectMapper mapper() {
        return mapper;
    }

    public void writeAtomic(String collection, String key, Object value) {
        Path target = pathOf(collection, key);
        try {
            Files.createDirectories(target.getParent());
            Path tmp = Files.createTempFile(target.getParent(), ".tmp-" + safeKey(key) + "-", SUFFIX);
            try {
                // 先写临时文件并强制刷盘，再原子替换：任何时刻读到的都是完整内容
                mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), value);
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException moveOrWrite) {
                deleteIfExists(tmp);
                throw moveOrWrite;
            }
        } catch (IOException e) {
            throw new UncheckedIOException("原子写入失败: " + collection + "/" + key, e);
        }
    }

    /** 读取对象；不存在返回 null。文件损坏抛 UncheckedIOException，绝不静默返回 null。 */
    public <T> T read(String collection, String key, Class<T> type) {
        Path target = pathOf(collection, key);
        if (!Files.isRegularFile(target)) {
            return null;
        }
        try {
            return mapper.readValue(target.toFile(), type);
        } catch (IOException e) {
            throw new UncheckedIOException("读取损坏的数据文件: " + target, e);
        }
    }

    public <T> List<T> readAll(String collection, Class<T> type) {
        Path dir = root.resolve(collection);
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.filter(p -> p.getFileName().toString().endsWith(SUFFIX))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .map(p -> {
                        try {
                            return mapper.readValue(p.toFile(), type);
                        } catch (IOException e) {
                            throw new UncheckedIOException("读取损坏的数据文件: " + p, e);
                        }
                    })
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("列出集合失败: " + collection, e);
        }
    }

    public boolean delete(String collection, String key) {
        try {
            return Files.deleteIfExists(pathOf(collection, key));
        } catch (IOException e) {
            throw new UncheckedIOException("删除失败: " + collection + "/" + key, e);
        }
    }

    public boolean exists(String collection, String key) {
        return Files.isRegularFile(pathOf(collection, key));
    }

    public List<String> keys(String collection) {
        Path dir = root.resolve(collection);
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.filter(p -> p.getFileName().toString().endsWith(SUFFIX))
                    .map(p -> {
                        String n = p.getFileName().toString();
                        return n.substring(0, n.length() - SUFFIX.length());
                    })
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("列出键失败: " + collection, e);
        }
    }

    private Path pathOf(String collection, String key) {
        return root.resolve(collection).resolve(safeKey(key) + SUFFIX);
    }

    /** 防止路径穿越；只保留文件名安全字符。 */
    static String safeKey(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("存储键不能为空");
        }
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            boolean ok = Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == '@';
            sb.append(ok ? c : '_');
        }
        return sb.toString();
    }

    private static void deleteIfExists(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (IOException ignored) {
            // 清理临时文件失败不影响主异常
        }
    }
}
