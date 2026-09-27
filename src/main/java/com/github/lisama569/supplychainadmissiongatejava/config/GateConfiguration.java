package com.github.lisama569.supplychainadmissiongatejava.config;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.persist.ArtifactRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.DecisionRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.IdempotencyRepository;
import com.github.lisama569.supplychainadmissiongatejava.persist.JsonStore;
import com.github.lisama569.supplychainadmissiongatejava.persist.PolicyRepository;
import com.github.lisama569.supplychainadmissiongatejava.security.HmacSigner;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 本地持久化与签名组件装配。 */
@Configuration
public class GateConfiguration {

    @Bean
    public JsonStore jsonStore(@Value("${gate.data-dir:./target/gate-data}") String dataDir) {
        return new JsonStore(Path.of(dataDir));
    }

    @Bean
    public IdempotencyRepository idempotencyRepository(JsonStore store) {
        return new IdempotencyRepository(store);
    }

    @Bean
    public ArtifactRepository artifactRepository(JsonStore store) {
        return new ArtifactRepository(store);
    }

    @Bean
    public PolicyRepository policyRepository(JsonStore store) {
        return new PolicyRepository(store);
    }

    @Bean
    public DecisionRepository decisionRepository(JsonStore store) {
        return new DecisionRepository(store);
    }

    /**
     * 加载本地 HMAC 密钥。未配置 gate.signing-key-path 时使用空密钥（仅允许上下文启动，
     * 真正验签会因签名不匹配而拒绝）；配置了但文件不可读则快速失败。
     */
    @Bean
    public HmacSigner hmacSigner(@Value("${gate.signing-key-path:}") String keyPath) {
        if (keyPath == null || keyPath.isBlank()) {
            return new HmacSigner(new byte[0]);
        }
        Path path = Path.of(keyPath);
        if (!Files.isRegularFile(path)) {
            throw new GateException(RejectionReason.ARGUMENT_INVALID,
                    "签名密钥文件不存在: " + keyPath);
        }
        try {
            byte[] key = Files.readAllBytes(path);
            if (key.length == 0) {
                throw new GateException(RejectionReason.ARGUMENT_INVALID,
                        "签名密钥文件为空: " + keyPath);
            }
            return new HmacSigner(key);
        } catch (IOException e) {
            throw new UncheckedIOException("读取签名密钥失败: " + keyPath, e);
        }
    }
}
