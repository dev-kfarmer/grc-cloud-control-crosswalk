# Unified Control Spec — S3 Encryption at Rest

**Status:** Design → build in progress
**Format:** Mirrors a unified-controls assessment structure ("assess once, comply with many")

---

## Approach

Single control, single cloud (AWS), three frameworks. One evidence pull normalized into a
common schema, evaluated against a framework-specific pass bar. This demonstrates
"assess once, comply with many" rather than three separate checks — the model a real
compliance automation platform uses to avoid re-collecting the same evidence per framework.

Assumption: buckets are enumerated via `list_buckets`; scope can later be narrowed to a
tagged subset (e.g. `Environment=prod`) to mirror how a real customer would scope evidence
collection instead of scanning every bucket in the account.

---

## Unified Control

| Field | Value |
|---|---|
| Unified Control ID | UC-04 |
| Unified Control Name | Data Encryption at Rest (S3) |
| Control Objective | Data stored in S3 is encrypted at rest to protect confidentiality in the event of unauthorized storage-layer access. |
| SOC 2 | CC6.1 |
| ISO 27001 | A.8.24 (Use of Cryptography) |
| NIST 800-53 | SC-28 (Protection of Information at Rest), SC-28(1) (Cryptographic Protection) |
| Mapping Notes & Confidence | High confidence. All three frameworks require encryption of data at rest as a baseline control; NIST SC-28(1) adds an explicit cryptographic-protection enhancement that maps most naturally to customer-managed KMS rather than provider-managed default encryption. Confidence: **High**. |

---

## Evidence

| Evidence ID | Artifact | Source | What "good" looks like |
|---|---|---|---|
| ER-01 | Bucket encryption configuration | AWS API — `s3:GetBucketEncryption` | `ServerSideEncryptionConfiguration` present and non-empty |
| ER-02 | KMS key ownership (if SSE-KMS) | AWS API — `kms:DescribeKey` | `KeyManager` field: `CUSTOMER` vs `AWS` |
| ER-03 | Bucket inventory / scope | AWS API — `s3:ListBuckets` | Full account bucket list, timestamped, to prove evidence completeness (no bucket silently excluded) |

## Evidence Feed (normalized schema)

```json
{
  "control_id": "UC-04",
  "resource_type": "s3_bucket",
  "resource_id": "example-bucket-name",
  "region": "us-east-1",
  "evidence_timestamp": "2026-07-20T00:00:00Z",
  "encryption_enabled": true,
  "sse_algorithm": "aws:kms",
  "kms_key_manager": "CUSTOMER",
  "raw_evidence": { "...": "full API response, retained for audit trail" }
}
```

One object. Framework verdicts are computed *from* this object — never re-fetched per framework.

---

## Automation Plan

- **Input:** AWS account, IAM role with read-only `s3:GetBucketEncryption`, `s3:ListBuckets`, `kms:DescribeKey`
- **Trigger:** Manual run for lab purposes; a real deployment would run on a schedule (e.g. daily) or event-driven via EventBridge on `s3:PutBucketEncryption` / `s3:DeleteBucketEncryption` CloudTrail events
- **Logic:**
  1. Enumerate all buckets
  2. For each bucket, call `GetBucketEncryption`; catch `ServerSideEncryptionConfigurationNotFoundError` as an explicit fail, not a crash
  3. If SSE-KMS, call `kms:DescribeKey` to resolve `KeyManager`
  4. Normalize into the evidence schema above
  5. Evaluate against each framework's pass bar (see below)
- **Exceptions:** Buckets tagged `compliance-exception=true` are excluded from fail-count but still logged with a `waived` status and a required `exception_reason` tag — undocumented exceptions are a fail, not a skip

## Pass/Fail Criteria (per framework, same evidence)

| Framework | Pass condition | Fail condition |
|---|---|---|
| SOC 2 CC6.1 | `encryption_enabled == true` (any algorithm) | No encryption config present |
| ISO 27001 A.8.24 | `encryption_enabled == true` (any algorithm) | No encryption config present |
| NIST 800-53 SC-28(1) | `sse_algorithm == "aws:kms"` **and** `kms_key_manager == "CUSTOMER"` | SSE-S3, no encryption, or AWS-managed KMS key |

## Finding: the SOC 2 / ISO fail branch is currently unreachable in live AWS (as of this build, 2026)

Since January 2023, AWS automatically applies SSE-S3 encryption to every S3 bucket in every
account by default, and this cannot be disabled. A bucket created with **zero** encryption
configuration still returns `GetEncryptionConfiguration` with `SSEAlgorithm: AES256` — verified
directly against a bucket in this lab that has no `server_side_encryption_configuration` block
in Terraform at all.

Practical effect: SOC 2 CC6.1 and ISO 27001 A.8.24's "no encryption config present" fail
condition, as written, describes a bucket state AWS no longer allows you to create through
normal API calls. Both frameworks predate AWS's default-encryption change and have not been
rewritten to account for it. The evidence collector's code still correctly implements the fail
condition (see `test_evidence_collector.py::test_unencrypted_bucket_fails_all_frameworks`,
which proves the logic using a mocked API response) — the test exists specifically *because*
live AWS no longer produces this state, so a mock is the only way left to verify the code
handles it correctly.

This does not weaken the demo; it sharpens it. It means NIST SC-28(1)'s customer-managed-key
requirement is now the **only** one of the three pass bars that still requires deliberate
customer action rather than relying on the cloud provider's baseline — which is a more
interesting, more current story than "can you tell if a box is checked."

## Risk & Audit Call-out

Buckets without an explicit encryption config return an API error rather than a "false"
value — a naive implementation that only checks for exceptions-as-crashes will silently
skip unencrypted buckets instead of failing them. This is the single most common false-negative
in evidence automation and is the first thing to unit-test.

## Priority / Impact

High — foundational control referenced across nearly every framework; strong automation
potential; clean API surface for a first build.

## Sources

- AWS `GetBucketEncryption` / `DescribeKey` API documentation
- NIST SP 800-53 Rev. 5, SC-28 and SC-28(1)
- ISO/IEC 27001:2022 Annex A, A.8.24
- SOC 2 Trust Services Criteria, CC6.1
