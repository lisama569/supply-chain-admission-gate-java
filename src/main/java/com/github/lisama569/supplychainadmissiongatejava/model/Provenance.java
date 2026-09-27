package com.github.lisama569.supplychainadmissiongatejava.model;

/**
 * 归一化后的来源（SLSA 风格）材料。
 *
 * @param builderId      构建者标识
 * @param sourceUri      源码地址
 * @param sourceRevision 源码版本标识
 * @param slsaLevel      SLSA 等级 0-4
 * @param digestAlg      制品摘要算法
 * @param digestHex      制品摘要十六进制
 */
public record Provenance(String builderId,
                         String sourceUri,
                         String sourceRevision,
                         int slsaLevel,
                         String digestAlg,
                         String digestHex) {
}
