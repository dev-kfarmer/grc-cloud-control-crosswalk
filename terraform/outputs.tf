output "test_buckets" {
  description = "All lab bucket names and their expected pass/fail case, for verifying the evidence collector"
  value = {
    sse_s3_aes256          = { name = aws_s3_bucket.sse_s3.id, expect_soc2_iso = "PASS", expect_nist = "FAIL" }
    sse_kms_aws_managed    = { name = aws_s3_bucket.sse_kms_aws_managed.id, expect_soc2_iso = "PASS", expect_nist = "FAIL" }
    sse_kms_customer_managed = { name = aws_s3_bucket.sse_kms_customer_managed.id, expect_soc2_iso = "PASS", expect_nist = "PASS" }
    baseline_default_only  = { name = aws_s3_bucket.baseline_default_only.id, expect_soc2_iso = "PASS", expect_nist = "FAIL" }
    waived_exception       = { name = aws_s3_bucket.waived_exception.id, expect_soc2_iso = "WAIVED", expect_nist = "WAIVED" }
  }
}

output "iam_policy_arn" {
  description = "ARN of the least-privilege policy attached to the lab user"
  value       = aws_iam_policy.evidence_readonly.arn
}
