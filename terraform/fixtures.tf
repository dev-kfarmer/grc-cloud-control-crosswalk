# Test fixtures for UC-04 (S3 Encryption at Rest).
# Five buckets, one per branch in the pass/fail matrix — the point is to prove
# the evidence collector against every case, not just the happy path.

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
}

# Case 1: SSE-S3 (AES-256) — passes SOC2/ISO, FAILS NIST SC-28(1) (not customer-managed KMS)
resource "aws_s3_bucket" "sse_s3" {
  bucket = "${var.bucket_prefix}-sse-s3-${local.suffix}"
  tags = {
    Project = "grc-evidence-lab"
    Case    = "sse-s3-aes256"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_s3" {
  bucket = aws_s3_bucket.sse_s3.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Case 2: SSE-KMS with AWS-managed key (aws/s3) — passes SOC2/ISO, FAILS NIST (not customer-managed)
resource "aws_s3_bucket" "sse_kms_aws_managed" {
  bucket = "${var.bucket_prefix}-sse-kms-aws-${local.suffix}"
  tags = {
    Project = "grc-evidence-lab"
    Case    = "sse-kms-aws-managed"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_kms_aws_managed" {
  bucket = aws_s3_bucket.sse_kms_aws_managed.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      # No kms_master_key_id specified -> defaults to the AWS-managed aws/s3 key
    }
  }
}

# Case 3: SSE-KMS with customer-managed key — PASSES all three frameworks, including NIST
resource "aws_kms_key" "customer_managed" {
  description             = "Customer-managed key for grc-evidence-lab (UC-04 passing case)"
  deletion_window_in_days = 7
  tags = {
    Project = "grc-evidence-lab"
  }
}

resource "aws_s3_bucket" "sse_kms_customer_managed" {
  bucket = "${var.bucket_prefix}-sse-kms-cmk-${local.suffix}"
  tags = {
    Project = "grc-evidence-lab"
    Case    = "sse-kms-customer-managed"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_kms_customer_managed" {
  bucket = aws_s3_bucket.sse_kms_customer_managed.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.customer_managed.arn
    }
  }
}

# Case 4: No encryption block configured at all — relies entirely on AWS's
# account-wide default (SSE-S3), which has applied automatically to every S3
# bucket since January 2023 and cannot be disabled. Passes SOC2/ISO (any
# encryption), FAILS NIST SC-28(1) (not a customer-managed key). See
# control-spec.md "Finding" section — this is why the FAIL-everything case
# from case-based S3 encryption checks is unreachable in live AWS today, and
# is instead proven only via a mocked test in test_evidence_collector.py.
resource "aws_s3_bucket" "baseline_default_only" {
  bucket = "${var.bucket_prefix}-baseline-default-only-${local.suffix}"
  tags = {
    Project = "grc-evidence-lab"
    Case    = "baseline-default-only"
  }
}

# Case 5: Documented exception — unencrypted but tagged as a waived exception.
# Proves the collector's exception logic (waived, not silently passed).
resource "aws_s3_bucket" "waived_exception" {
  bucket = "${var.bucket_prefix}-waived-exception-${local.suffix}"
  tags = {
    Project             = "grc-evidence-lab"
    Case                = "waived-exception"
    compliance-exception = "true"
    exception_reason    = "Legacy migration bucket - decommission scheduled Q3 - tracked in JIRA-1234"
  }
}
