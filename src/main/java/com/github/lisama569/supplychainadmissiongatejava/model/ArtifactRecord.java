package com.github.lisama569.supplychainadmissiongatejava.model;

import java.time.Instant;

/**
 * 一次成功导入后形成的制品档案（快照）。
 *
 * @param artifactKey   制品逻辑标识：name@version
 * @param name          制品名
 * @param version       制品版本
 * @param digestHex     摘要十六进制
 * @param manifest      归一化清单
 * @param provenance    归一化来源（可为空，表示无来源材料）
 * @param sourceChannel 来源材料渠道（本地样本文件名）
 * @param importedAt    导入时间
 * @param importedBy    导入者
 * @param importRequestId 导入请求幂等键
 */
public record ArtifactRecord(String artifactKey,
                             String name,
                             String version,
                             String digestHex,
                             NormalizedManifest manifest,
                             Provenance provenance,
                             String sourceChannel,
                             Instant importedAt,
                             String importedBy,
                             String importRequestId) {

    public ArtifactRecord withProvenance(Provenance provenance, String sourceChannel) {
        return new ArtifactRecord(artifactKey, name, version, digestHex, manifest, provenance,
                sourceChannel, importedAt, importedBy, importRequestId);
    }
}
