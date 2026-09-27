import json, hashlib, hmac, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "samples"
key = (ROOT / "keys/hmac.key").read_bytes()
valid = ROOT / "valid"
invalid = ROOT / "invalid"

def sha256_of(payload: dict, marker: str) -> str:
    # 制品摘要在本地模拟中取“规范化 payload（去掉 markers）”的 SHA-256，保证可复现
    clone = json.loads(json.dumps(payload))
    return hashlib.sha256(json.dumps(clone, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def sign(doc: dict, name: str, outdir=valid, corrupt=False):
    raw = json.dumps(doc, indent=2, ensure_ascii=False).encode()
    mac = hmac.new(key, raw, hashlib.sha256).hexdigest()
    if corrupt:
        mac = "0" * 64
    (outdir / name).write_bytes(raw)
    (outdir / (name + ".sig")).write_text(mac + "\n")
    return raw, mac

# ---------- 1. SPDX：含高危漏洞的组件 + Apache-2.0（用于“漏洞主导”判定） ----------
spdx_payload = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "payments-service",
    "packages": [],
    "vulnerabilities": [],
}
artifact_digest = sha256_of({"name": "payments-service", "version": "4.2.0"}, None)
spdx_payload["packages"] = [
    {
        "SPDXID": "SPDXRef-Package-payments-service",
        "name": "payments-service",
        "versionInfo": "4.2.0",
        "supplier": "Organization: acme-corp",
        "licenseDeclared": "Apache-2.0",
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_digest}],
    },
    {
        "SPDXID": "SPDXRef-Package-log4j-core",
        "name": "log4j-core",
        "versionInfo": "2.14.0",
        "supplier": "Organization: apache",
        "licenseDeclared": "Apache-2.0",
        "checksums": [{"algorithm": "SHA256",
                       "checksumValue": hashlib.sha256(b"log4j-core-2.14.0").hexdigest()}],
    },
    {
        "SPDXID": "SPDXRef-Package-legacy-math",
        "name": "legacy-math",
        "versionInfo": "1.0.0",
        "licenseDeclared": "AGPL-3.0-only",
        "checksums": [{"algorithm": "SHA256",
                       "checksumValue": hashlib.sha256(b"legacy-math-1.0.0").hexdigest()}],
    },
]
spdx_payload["vulnerabilities"] = [
    {"id": "CVE-2021-44228", "affected": "log4j-core", "severity": "CRITICAL", "cvss": 10.0},
    {"id": "CVE-2020-9999", "affected": "legacy-math", "severity": "LOW", "cvss": 2.1},
]
spdx_raw, spdx_mac = sign(spdx_payload, "spdx-2.3.json")

# ---------- 2. CycloneDX：干净制品（应 ADMITTED，配合可信来源） ----------
cdx_artifact_digest = hashlib.sha256(b"edge-gateway:7.0.1").hexdigest()
cdx = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "edge-gateway",
            "version": "7.0.1",
            "supplier": {"name": "acme-corp"},
            "hashes": [{"alg": "SHA-256", "content": cdx_artifact_digest}],
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        }
    },
    "components": [
        {
            "type": "library",
            "name": "jackson-databind",
            "version": "2.17.2",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2",
            "hashes": [{"alg": "SHA-256",
                        "content": hashlib.sha256(b"jackson-databind-2.17.2").hexdigest()}],
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        }
    ],
    "vulnerabilities": [],
}
sign(cdx, "cyclonedx-1.5.json")

# 与 CycloneDX 匹配的、可信来源材料
prov_good = {
    "provenanceVersion": 1,
    "buildType": "https://acme-corp.example/buildTypes/mvn",
    "slsaLevel": 3,
    "subject": {"digestAlg": "SHA-256", "digest": cdx_artifact_digest},
    "builder": {"id": "pkg:generic/acme-corp/trusted-builder@v1"},
    "source": {"uri": "git+https://scm.acme-corp.example/gateway/edge-gateway",
               "revision": "sha1:abc123def456"},
}
# builderId 必须命中默认策略可信列表，故采用策略默认值
prov_good["builder"]["id"] = "pkg:generic/trusted-builder@v1"
sign(prov_good, "provenance-cyclonedx-v1.json")

# 与 SPDX 匹配的来源材料（可信构建者 + L3，但制品仍因漏洞被隔离）
prov_spdx = {
    "provenanceVersion": 1,
    "buildType": "https://acme-corp.example/buildTypes/mvn",
    "slsaLevel": 3,
    "subject": {"digestAlg": "SHA-256", "digest": artifact_digest},
    "builder": {"id": "pkg:generic/trusted-builder@v1"},
    "source": {"uri": "git+https://scm.acme-corp.example/payments/payments-service",
               "revision": "sha1:deadbeef"},
}
sign(prov_spdx, "provenance-spdx-v1.json")

# ---------- 3. 内部格式：三维度同时命中（漏洞 + AGPL + 不可信来源/低 SLSA） ----------
int_digest = hashlib.sha256(b"billing-core:2.5.0").hexdigest()
internal = {
    "manifestVersion": 1,
    "artifact": {
        "name": "billing-core",
        "version": "2.5.0",
        "supplier": "acme-corp",
        "digestAlg": "SHA-256",
        "digest": int_digest,
    },
    "licenses": ["Apache-2.0", "AGPL-3.0-only"],
    "components": [
        {
            "name": "fastjson",
            "version": "1.2.80",
            "license": "Apache-2.0",
            "vulnerabilities": [
                {"id": "CVE-2022-25845", "severity": "HIGH", "cvss": 8.1}
            ],
        }
    ],
}
sign(internal, "manifest-v1.json")

# 内部格式的“矛盾来源”：摘要不匹配
prov_bad_digest = json.loads(json.dumps(prov_spdx))
prov_bad_digest["subject"]["digest"] = "f" * 64
sign(prov_bad_digest, "provenance-digest-mismatch-v1.json", outdir=invalid)

# 内部格式的“来源矛盾”：摘要匹配但构建者归属不一致
prov_bad_org = {
    "provenanceVersion": 1,
    "buildType": "https://other.example/build",
    "slsaLevel": 1,
    "subject": {"digestAlg": "SHA-256", "digest": int_digest},
    "builder": {"id": "pkg:generic/shady-vendor/builder@v9"},
    "source": {"uri": "git+https://evil.example/billing-core", "revision": "sha1:1111"},
}
sign(prov_bad_org, "provenance-conflicting-source-v1.json", outdir=invalid)

# 给内部制品一个“合法但不可信（低 SLSA + 不可信 builder）”的来源
prov_internal = {
    "provenanceVersion": 1,
    "buildType": "https://acme-corp.example/buildTypes/mvn",
    "slsaLevel": 1,
    "subject": {"digestAlg": "SHA-256", "digest": int_digest},
    "builder": {"id": "pkg:generic/acme-corp/local-laptop-builder@v1"},
    "source": {"uri": "git+https://scm.acme-corp.example/billing/billing-core",
               "revision": "sha1:cafe"},
}
sign(prov_internal, "provenance-internal-v1.json")

# ---------- 异常清单样本 ----------
# 无效签名：内容合法但签名错误
sign(spdx_payload, "spdx-bad-signature.json", outdir=invalid, corrupt=True)

# 版本不兼容（SPDX 2.2 不受支持）
old = json.loads(json.dumps(spdx_payload))
old["spdxVersion"] = "SPDX-2.2"
(old_raw := json.dumps(old, indent=2).encode())
(invalid / "spdx-bad-version.json").write_bytes(old_raw)
(invalid / "spdx-bad-version.json.sig").write_text(
    hmac.new(key, old_raw, hashlib.sha256).hexdigest() + "\n")

# 字段缺失（缺少 packages）
missing = {"spdxVersion": "SPDX-2.3", "name": "no-packages"}
missing_raw = json.dumps(missing, indent=2).encode()
(invalid / "spdx-missing-fields.json").write_bytes(missing_raw)
(invalid / "spdx-missing-fields.json.sig").write_text(
    hmac.new(key, missing_raw, hashlib.sha256).hexdigest() + "\n")

# CycloneDX 版本不兼容
cdx_old = json.loads(json.dumps(cdx))
cdx_old["specVersion"] = "1.4"
cdx_old_raw = json.dumps(cdx_old, indent=2).encode()
(invalid / "cyclonedx-bad-version.json").write_bytes(cdx_old_raw)
(invalid / "cyclonedx-bad-version.json.sig").write_text(
    hmac.new(key, cdx_old_raw, hashlib.sha256).hexdigest() + "\n")

# 内部格式版本不兼容
int_old = json.loads(json.dumps(internal))
int_old["manifestVersion"] = 99
int_old_raw = json.dumps(int_old, indent=2).encode()
(invalid / "manifest-bad-version.json").write_bytes(int_old_raw)
(invalid / "manifest-bad-version.json.sig").write_text(
    hmac.new(key, int_old_raw, hashlib.sha256).hexdigest() + "\n")

# 不支持的算法（MD5 checksum）
md5_doc = json.loads(json.dumps(spdx_payload))
md5_doc["packages"][0]["checksums"] = [
    {"algorithm": "MD5", "checksumValue": "d41d8cd98f00b204e9800998ecf8427e"}]
md5_raw = json.dumps(md5_doc, indent=2).encode()
(invalid / "spdx-md5-algorithm.json").write_bytes(md5_raw)
(invalid / "spdx-md5-algorithm.json.sig").write_text(
    hmac.new(key, md5_raw, hashlib.sha256).hexdigest() + "\n")

# 来源材料版本不兼容（合法签名）
prov_old = json.loads(json.dumps(prov_spdx))
prov_old["provenanceVersion"] = 2
prov_old_raw = json.dumps(prov_old, indent=2).encode()
(invalid / "provenance-bad-version-v1.json").write_bytes(prov_old_raw)
(invalid / "provenance-bad-version-v1.json.sig").write_text(
    hmac.new(key, prov_old_raw, hashlib.sha256).hexdigest() + "\n")

# 损坏 JSON（不是合法 JSON）
(invalid / "broken.json").write_bytes(b"{ this is not valid json ,,,")
(invalid / "broken.json.sig").write_text(
    hmac.new(key, b"{ this is not valid json ,,,", hashlib.sha256).hexdigest() + "\n")

print("samples generated:")
for p in sorted(valid.glob("*")):
    print(" valid/", p.name)
for p in sorted(invalid.glob("*")):
    print(" invalid/", p.name)
