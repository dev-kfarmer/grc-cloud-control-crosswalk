# The IAM user itself is a one-time console bootstrap exception (see README).
# Terraform only manages the *policy* attached to it — the permission boundary,
# not the identity. This is the piece that should always be code-reviewed.

resource "aws_iam_policy" "evidence_readonly" {
  name        = "grc-lab-s3-encryption-evidence-readonly"
  description = "Least-privilege read-only access for the S3 encryption evidence collector (UC-04)"
  policy      = file("${path.module}/../iam/readonly-evidence-policy.json")
}

resource "aws_iam_user_policy_attachment" "lab_user_evidence_readonly" {
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.evidence_readonly.arn
}
