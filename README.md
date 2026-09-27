# Supply Chain Admission Gate (Java)

本地软件供应链准入校验服务。使用工作区内的本地样本（`samples/`）模拟依赖清单、
签名与来源材料，对不同格式与异常输入给出一致、可追溯、可复现的判定结论。

## 支持的材料格式

| 格式 | 文件示例 | 识别方式 | 必需字段 |
|---|---|---|---|
| CycloneDX JSON 1.x | `samples/manifest-cyclonedx.json` | `bomFormat: "CycloneDX"` | `specVersion`、`components[].name/version` |
| SPDX JSON 2.x | `samples/manifest-spdx.json` | `spdxVersion: "SPDX-2.*"` | `packages[].name/versionInfo` |
| CSV 清单 | `samples/manifest.csv` | 固定表头 `name,version,purl,license,vulnerabilities,supplier,sha256` | `name`、`version` |

来源材料（provenance）为 JSON：`issuer`、`repository`、`signedPayload`、
`signature`、`declaredSupplier`。签名为 `HMAC-SHA256(issuer密钥, signedPayload)`
的小写十六进制，issuer 密钥通过 `gate.issuer-keys=<issuer>=<secret>,...` 本地配置。

## 准入与隔离规则

所有清单先归一化为统一的 `Artifact` 模型，再由确定性判定引擎评估：

- 漏洞数 > `policy.maxVulnerabilities` → `VULNERABILITY_RISK`
- 许可缺失或命中 `policy.bannedLicenses` → `LICENSE_RISK`
- 签发者不在 `policy.trustedIssuers` → `UNTRUSTED_SOURCE`

组合规则（固定优先级，结论确定且可解释）：

- 命中漏洞或许可风险 → **REJECT**（所有命中原因全部列出）
- 仅来源不可信 → **QUARANTINE**
- 无风险 → **ADMIT**

异常输入不会静默通过，拒绝原因可区分：`MISSING_FIELD`、
`UNSUPPORTED_FORMAT_VERSION`、`PROVENANCE_CONFLICT`（来源声明与清单矛盾）、
`INVALID_SIGNATURE`、`MALFORMED_INPUT`、`PERMISSION_DENIED`。

## 权限边界

| 角色 | 允许操作 |
|---|---|
| `ADMISSION_OPERATOR` | IMPORT（提交清单并判定） |
| `QUARANTINE_OPERATOR` | IMPORT |
| `POLICY_ADMIN` | POLICY_PUBLISH（发布策略） |
| `OVERRIDE_ADMIN` | IMPORT、OVERRIDE（覆盖判定为 ADMIT，须附理由） |

越权操作抛出 `PERMISSION_DENIED`（REST 层映射为 403）。

## 并发与幂等语义

- **幂等**：提交必须携带 `idempotencyKey`；重复提交（含并发重复）返回首次记录，
  审计日志只追加一条。覆盖操作以 `override:<decisionId>` 为键，同样幂等。
- **策略版本**：`PolicyStore` 原子发布，版本号单调递增；每次判定只读取一个
  策略快照，不会出现半更新或混合版本结果。判定记录中固化 `policyVersion`。
- **可追溯**：所有判定（含被拒绝的输入）以 JSON Lines 追加写入
  `gate.audit-file`（默认 `data/audit.log`），服务重启后历史判定依据
  （输入摘要、策略版本、证据）仍可查询。
- **可复现**：相同输入 + 相同策略版本 ⇒ 相同 verdict/reasons/evidence；
  `decisionId` 由 `(idempotencyKey, policyVersion, inputDigest)` 确定性导出。

## REST API

- `POST /api/gate/submit`（头 `X-Role`）：提交清单 + 来源材料
- `POST /api/gate/policy`（`X-Role: POLICY_ADMIN`）：发布新策略
- `GET  /api/gate/policy`：当前策略
- `POST /api/gate/decisions/{id}/override`（`X-Role: OVERRIDE_ADMIN`）：覆盖判定
- `GET  /api/gate/decisions[/{id}]`：判定历史 / 单条判定

## 本地验证

```bash
mvn test          # 运行全部测试（20 个）
mvn spring-boot:run
```

测试覆盖：多格式导入、无效签名、字段缺失、版本不兼容、来源矛盾、越权操作、
并发策略发布与并发重复提交、重启后历史可追溯。单测日志打印输入摘要
（`inputDigest` 前 16 位）、`policyVersion` 与判定依据（`evidence`）。

`samples/` 中的签名可用以下方式重新生成：

```bash
python3 -c "import hmac,hashlib;print(hmac.new(b'secret-acme-key',b'acme-release:widget-core@2.1.0',hashlib.sha256).hexdigest())"
```
