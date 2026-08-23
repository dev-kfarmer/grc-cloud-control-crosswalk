# Registers GitHub's OIDC token issuer with AWS.
# This alone grants no access -- it only makes AWS willing to
# evaluate tokens GitHub signs. Who may actually assume a role
# is decided by the trust policy in the next step.
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  # "sts.amazonaws.com" is the intended audience of the token --
  # GitHub mints a token addressed specifically to AWS STS, so a
  # token issued for some other service can't be replayed here.
  client_id_list = ["sts.amazonaws.com"]
}

# The trust policy: WHO may assume this role.
# The provider registration said "AWS recognizes GitHub-issued IDs."
# This says "and only this repo, on this branch, may come in."
data "aws_iam_policy_document" "github_actions_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    # Audience check: the token must be addressed to AWS STS.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Subject check: this is the line that matters. Without it, ANY
    # GitHub repo on the internet could assume this role. StringEquals
    # (not StringLike) means no wildcards -- this exact repo, this
    # exact branch, nothing else.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:dev-kfarmer/grc-cloud-control-crosswalk:ref:refs/heads/main"]
    }
  }
}

# The role itself. Assumable only under the conditions above.
resource "aws_iam_role" "github_actions_evidence" {
  name               = "grc-lab-github-actions-evidence"
  description        = "Assumed by GitHub Actions via OIDC to run the S3 encryption evidence collector"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume.json
  max_session_duration = 3600
}

# Reuses the SAME least-privilege policy the local collector uses.
# One permission definition, two ways of arriving at it.
resource "aws_iam_role_policy_attachment" "github_actions_evidence" {
  role       = aws_iam_role.github_actions_evidence.name
  policy_arn = aws_iam_policy.evidence_readonly.arn
}