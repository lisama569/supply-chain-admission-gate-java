# 本地软件供应链准入校验（Supply Chain Admission Gate）

一套完全运行在工作区内的**本地**软件供应链准入校验能力：用本地样本模拟依赖清单、
签名与来源（Provenance）材料，对不同格式与异常输入给出**一致、可区分、可追溯、可复现**
的准入结论。无外部数据库/网络依赖，签名用 HMAC-SHA256 本地模拟，持久化为原子 JSON 文件。

## 1. 能力总览

| 能力 | 说明 |
| --- | --- |
| 多格式导入与归一化 | SPDX 2.3、CycloneDX 1.5、内部 manifest-v1 统一归一化；SLSA 风格 provenance-v1 来源材料 |
| 签名校验 | 所有材料必须对**原始字节**携带 HMAC-SHA256 十六进制签名；缺签/错签直接拒绝 |
| 异常可区分 | 字段缺失、版本不兼容、算法不支持、来源矛盾、签名无效等各有独立拒绝原因，绝不静默通过 |
| 角色与权限 | GUEST / ANALYST / APPROVER / POLICY_ADMIN / SECURITY_OFFICER 五种角色，越权返回 403 |
| 确定性判定 | 漏洞 > 许可 > 来源 固定优先级；三维度同时命中也有唯一、可解释结论 |
| 策略版本与并发 | 策略不可变版本化，乐观锁发布；判定读策略快照，无半更新/混合版本 |
| 幂等 | 导入、判定、隔离、覆盖、发布均支持幂等键；同键同体返回同一结果，同键异体返回冲突 |
| 可追溯 | 每次判定落不可变记录（全部依据 + 策略版本 + 摘要），服务重启后仍可还原时间线 |

## 2. 工作区样本材料

样本位于 [`samples/`](samples)，签名密钥为 `samples/keys/hmac.key`
（**仅本地模拟，请勿用于真实场景**）。每个材料文件都有一个同名 `.sig` 侧车文件，
内容为对材料原始字节的 HMAC-SHA256 十六进制。

### 2.1 支持的材料格式

| 类别 | 文件示例 | 版本字段（仅支持的值） | 说明 |
| --- | --- | --- | --- |
| SPDX 清单 | `valid/spdx-2.3.json` | `spdxVersion = SPDX-2.3` | 文档同名 package 为制品本体；`packages` 为组件；`vulnerabilities[].affected` 关联组件 |
| CycloneDX 清单 | `valid/cyclonedx-1.5.json` | `specVersion = 1.5` | `metadata.component` 为制品本体；`components` 为组件；`vulnerabilities[].ratings` 取严重等级 |
| 内部清单 | `valid/manifest-v1.json` | `manifestVersion = 1` | `artifact` + `components` + `licenses` 的简洁结构 |
| 来源材料 | `valid/provenance-*-v1.json` | `provenanceVersion = 1` | `subject`（摘要）+ `builder.id` + `slsaLevel` + `source` |

所有摘要算法**仅支持 SHA-256**（64 位小写十六进制）；MD5/SHA1 等会以
`UNSUPPORTED_ALGORITHM` 拒绝。

重新生成全部样本与签名（例如修改样本后）：

```bash
python3 tools/gen_samples.py   # 脚本会重写 samples/valid 与 samples/invalid
```

### 2.2 异常样本与拒绝原因对照

| 样本 | 拒绝原因 `RejectionReason` |
| --- | --- |
| `invalid/spdx-bad-signature.json` | `INVALID_SIGNATURE`（内容合法但签名错误） |
| 缺少签名 / 空白签名 | `MISSING_SIGNATURE` |
| `invalid/spdx-bad-version.json` / `cyclonedx-bad-version.json` / `manifest-bad-version.json` / `provenance-bad-version-v1.json` | `INCOMPATIBLE_VERSION` |
| `invalid/spdx-missing-fields.json` | `MISSING_FIELD` |
| `invalid/broken.json` | `MALFORMED_DOCUMENT` |
| `invalid/spdx-md5-algorithm.json` | `UNSUPPORTED_ALGORITHM` |
| 未知格式（如 `swid`） | `UNSUPPORTED_FORMAT` |
| `invalid/provenance-digest-mismatch-v1.json` | `PROVENANCE_MISMATCH`（来源摘要 ≠ 清单摘要） |
| `invalid/provenance-conflicting-source-v1.json` | `INCONSISTENT_SOURCE`（非可信构建者且与 supplier 归属矛盾） |
| 缺少来源材料就要求准入 | 判定依据 `PROV-MISSING`（隔离），API 直接附来源缺失则 `MISSING_PROVENANCE` |
| 同幂等键不同请求体 | `DUPLICATE_CONFLICT`（HTTP 409） |
| 策略基线版本过期 | `POLICY_VERSION_CONFLICT`（HTTP 409） |
| 越权 | `FORBIDDEN`（HTTP 403） |

## 3. 准入与隔离规则

内置默认策略（未发布任何版本时为 v0）：

- 漏洞：组件或清单声明的漏洞严重等级 **≥ HIGH** 即隔离（`VULN-SEVERITY-THRESHOLD`）；
- 许可：许可证命中禁止清单（默认 `AGPL-3.0-only`、`AGPL-3.0-or-later`）或为已知
  Copyleft 且策略开启 `blockCopyleft` 时隔离（`LICENSE-BLOCKED` / `LICENSE-COPYLEFT`）；
- 来源：缺来源（`PROV-MISSING`）、SLSA 等级低于要求（默认 ≥ L2，`PROV-SLSA-LEVEL`）、
  构建者不在可信列表（默认要求 `pkg:generic/trusted-builder@v1`，`PROV-UNTRUSTED-BUILDER`）时隔离。

**多风险优先级（确定性）**：当漏洞、许可、来源三类风险同时命中时，按
`VULNERABILITY > LICENSE > PROVENANCE` 决定最终状态，所有命中依据仍完整保留在判定记录中，
`rationale` 字段逐条解释主导风险与全部依据。同输入 + 同策略版本永远产生同结论（已由
`DecisionDeterminismTest` 在两个独立数据目录间交叉验证）。

人工操作：

- **人工隔离**（APPROVER 及以上）：产生 `MANUAL-QUARANTINE` 依据，状态强制为隔离；
- **安全覆盖**（仅 SECURITY_OFFICER）：可覆盖为 `ADMITTED`/`QUARANTINED`，必须给原因；
  被覆盖结论的全部依据保留在新记录中，并记录 `overriddenBy` 与覆盖原因。

## 4. 权限边界

| 角色 | 导入材料 | 准入判定 | 人工隔离 | 发布策略 | 安全覆盖 |
| --- | :---: | :---: | :---: | :---: | :---: |
| GUEST | ✗ | ✗ | ✗ | ✗ | ✗ |
| ANALYST | ✓ | ✗ | ✗ | ✗ | ✗ |
| APPROVER | ✓ | ✓ | ✓ | ✗ | ✗ |
| POLICY_ADMIN | ✗ | ✗ | ✗ | ✓ | ✗ |
| SECURITY_OFFICER | ✓ | ✓ | ✓ | ✓ | ✓ |

未知角色名一律按 GUEST（最小权限）处理，不会因拼写/大小写问题提权。

## 5. 并发与幂等语义

### 5.1 幂等键

每个写操作都必须携带 `requestId`。服务对请求体（含操作类型与业务键）取 SHA-256：

- 同键 + 同体：返回**第一次**的结果引用（同一制品/同一判定 ID/同一策略版本），不产生重复记录；
- 同键 + 异体：返回 `DUPLICATE_CONFLICT`（409），避免键复用造成的错误重放；
- 键缺失：`MISSING_FIELD`（400）。

判定结果的 ID 由操作与幂等键派生：`dec-<id>`（自动判定）、`qtn-<id>`（人工隔离）、
`ovr-<id>`（覆盖）。

### 5.2 并发

- 导入/判定/发布服务方法在单实例内同步串行化“检查-执行-落盘”，配合仓储锁，
  保证并发同键导入只落一条记录（`ConcurrentImportTest`，10 并发 → 1 条）；
- 策略发布使用**乐观锁**：请求需带 `expectedVersion`，仓储在同一把锁内完成
  “读当前版本 → 比较基线 → 落不可变版本文件 → 原子切换 current 指针”。
  12 个同基线并发发布恰好 1 个成功、11 个 `POLICY_VERSION_CONFLICT`
  （`IdempotencyAndConcurrencyTest`）；
- 判定开始时一次性读取“制品快照 + 当前策略快照”，整个评估只读快照，因此与发布并发时，
  判定只能观察到完整的 vN 或 vN+1，绝无混合版本；
- 文件写入采用“临时文件 + 原子 move”，崩溃时不会留下半截 JSON。

## 6. 持久化与重启追溯

数据目录（默认 `./target/gate-data`，可用 `gate.data-dir` 覆盖）布局：

```
gate-data/
├── artifacts/     <name@version>.json   制品 + 归一化清单 + 来源快照
├── policies/      v<N>.json（不可变版本）、current.json（当前版本指针）
├── decisions/     <decisionId>.json      每次判定/隔离/覆盖的完整依据
└── idempotency/   <requestId>.json       幂等键 -> 请求体哈希 -> 结果引用
```

`PersistenceRestartTest` 丢弃内存对象后用同一目录重新装配，验证制品、来源、当前策略版本、
自动判定、人工隔离与安全覆盖均可恢复，且时间线顺序可重建。

## 7. REST 接口（本地验证用）

角色通过请求头 `X-User`、`X-Role` 模拟，清单/来源内容用 Base64 传输：

| 方法与路径 | 所需角色 | 说明 |
| --- | --- | --- |
| `POST /api/gate/artifacts/imports` | ANALYST+ | 导入签名清单 |
| `POST /api/gate/artifacts/{key}/provenance` | ANALYST+ | 附加签名来源材料 |
| `POST /api/gate/artifacts/{key}/decisions` | APPROVER+ | 执行自动准入判定 |
| `POST /api/gate/artifacts/{key}/quarantine` | APPROVER+ | 人工隔离（需 reason） |
| `POST /api/gate/artifacts/{key}/override` | SECURITY_OFFICER | 安全覆盖（需 targetStatus、reason） |
| `GET  /api/gate/decisions/{id}` | 任意 | 查询单次判定依据 |
| `GET  /api/gate/artifacts/{key}/decisions` | 任意 | 制品判定时间线 |
| `GET  /api/gate/policies/current` | 任意 | 当前策略 |
| `GET  /api/gate/policies/v{n}` | 任意 | 指定历史版本 |
| `POST /api/gate/policies` | POLICY_ADMIN / SECURITY_OFFICER | 乐观锁发布新版本 |

错误响应统一为 `{"reason": "<拒绝原因枚举>", "message": "<可读说明>"}`，
状态码：400（输入/格式/签名等）、403（越权）、404（不存在）、409（幂等冲突/版本冲突）。

## 8. 本地验证方法

要求：JDK 21+、Maven 3.9+（离线仓库可用 `mvn -o`）。

```bash
# 全量测试（33 个用例：多格式导入、无效签名、越权、策略并发、重复提交、重启追溯、REST）
mvn test

# 离线全量测试
mvn -o test

# 单类
mvn -o test -Dtest=DecisionDeterminismTest
```

单测日志会打印**输入摘要、策略版本与判定依据**，例如：

```
==== 判定日志 [three-risks] ====
输入摘要(sha256)=..., 输入字节数=..., 策略版本=v0, 最终状态=QUARANTINED
  依据1: [VULNERABILITY/HIGH] VULN-SEVERITY-THRESHOLD -> 漏洞 CVE-2022-25845 ...
  依据2: [LICENSE/HIGH] LICENSE-BLOCKED -> 许可证 AGPL-3.0-only ...
  依据3: [PROVENANCE/MEDIUM] PROV-SLSA-LEVEL -> SLSA 等级 L1 低于 ...
  依据4: [PROVENANCE/HIGH] PROV-UNTRUSTED-BUILDER -> 构建者 ... 不在可信列表 ...
```

手动启动服务后用 curl 走一遍（端口见启动日志，`server.port=0` 为随机端口）：

```bash
mvn -o spring-boot:run
# 导入
curl -s -X POST localhost:$PORT/api/gate/artifacts/imports \
  -H 'X-User: alice' -H 'X-Role: analyst' -H 'Content-Type: application/json' \
  -d "{\"requestId\":\"curl-1\",\"format\":\"cyclonedx\",
       \"manifestBase64\":\"$(base64 -w0 samples/valid/cyclonedx-1.5.json)\",
       \"signatureHex\":\"$(tr -d '\n' < samples/valid/cyclonedx-1.5.json.sig)\"}"
```

## 9. 测试覆盖索引

| 测试类 | 覆盖点 |
| --- | --- |
| `ImportRejectionTest` | 三格式归一化、无效/缺失签名、各格式版本不兼容、缺字段、坏 JSON、不支持算法、未知格式、来源摘要矛盾、来源归属矛盾 |
| `DecisionDeterminismTest` | 干净制品准入、三维度同时命中以漏洞主导且全部依据保留、跨目录可复现、缺来源、策略版本改变结论并记录版本 |
| `RbacTest` | 五种角色的允许/拒绝矩阵、仅安全官员可覆盖 |
| `IdempotencyAndConcurrencyTest` | 导入/判定/发布重复提交幂等、同键异体冲突、12 路同基线并发发布仅 1 成功、发布与判定并发无混合版本 |
| `ConcurrentImportTest` | 10 路同键并发导入仅产生 1 条制品 |
| `PersistenceRestartTest` | 重启后制品/来源/策略/判定时间线完整追溯 |
| `WebApiTest` | REST 全链路状态码：200/201、400 INVALID_SIGNATURE、403 FORBIDDEN、409 POLICY_VERSION_CONFLICT |

## 10. 边界与非目标（本地模拟）

- HMAC 共享密钥仅用于工作区样本；真实供应链应使用非对称签名（如 Sigstore/PKI）与验根；
- 许可证 Copyleft 分类使用内置简化集合，真实场景应接入完整 SPDX 许可证矩阵；
- 并发保证针对单实例（JVM 内锁 + 原子文件）；多实例部署需将仓储换成带事务/行锁的存储；
- 供应商与构建者归属比对为本地确定性启发式（可信构建者豁免），真实场景应对照受信注册表。
