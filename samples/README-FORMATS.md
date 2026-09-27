# 样本材料格式说明（工作区本地模拟）

所有样本由 `tools/gen_samples.py` 生成，可用 `python3 tools/gen_samples.py` 重新生成。
密钥固定为 `keys/hmac.key`，因此生成结果可复现。

## 签名

- 算法：HMAC-SHA256
- 输入：材料文件的**原始字节**
- 携带：同名 `.sig` 侧车文件，内容为小写十六进制 MAC（末尾允许换行）
- 无效签名样本 `invalid/spdx-bad-signature.json` 的 `.sig` 被故意置为 64 个 0

## 格式与版本门禁

| 格式 | 版本字段 | 接受值 | 关键必填内容 |
| --- | --- | --- | --- |
| SPDX JSON | `spdxVersion` | `SPDX-2.3` | `name`、非空 `packages`、每个包 `name/versionInfo/checksums(SHA256)` |
| CycloneDX JSON | `specVersion` | `1.5` | `metadata.component.name/version/hashes(SHA-256)` |
| 内部 manifest | `manifestVersion` | `1`（整数） | `artifact.name/version/digestAlg=SHA-256/digest` |
| 来源 provenance | `provenanceVersion` | `1`（整数） | `subject.digestAlg/digest`、`builder.id`、`slsaLevel(0-4)`、`source.uri/revision` |

## 制品摘要

样本制品的 SHA-256 摘要是构造数据的一部分（部分取规范化 JSON 的哈希，
部分取固定字节串哈希），来源材料的 `subject.digest` 必须与清单摘要严格一致，
否则以 `PROVENANCE_MISMATCH` 拒绝。
