# S3 encryption evidence collector

Reads the encryption setting on every S3 bucket in an AWS account and checks it
against three compliance frameworks in one pass: SOC 2 CC6.1, ISO 27001 A.8.24,
and NIST 800-53 SC-28(1).

The idea is to collect the evidence once and grade it against each framework,
instead of running a separate check per framework.

**Visual overview:** https://dev-kfarmer.github.io/grc-s3-encryption-crosswalk/visual-overview.html
— the pipeline, the pass/fail matrix, and the exception register on one page.

## Why the frameworks disagree

The three don't set the same bar:

- SOC 2 and ISO accept any server-side encryption.
- NIST SC-28(1) passes only if the bucket uses SSE-KMS with a customer-managed
  key. An AWS-managed key doesn't count.

So the same bucket can pass two frameworks and fail the third. Reading a control
closely enough to know where that line falls is the skill this project is meant
to show.

## What's in here

| Path | Purpose |
|---|---|
| `control-spec.md` | The control definition: evidence needed, pass/fail per framework, exception rules. Written before any code. |
| `iam/readonly-evidence-policy.json` | The five read-only permissions the collector uses. No write access. |
| `terraform/` | Stands up a throwaway test environment: five buckets (one per outcome), a customer-managed KMS key, and the IAM policy above. |
| `evidence_collector.py` | Reads each bucket and grades it against all three frameworks from one evidence pull. |
| `test_evidence_collector.py` | Unit tests with mocked AWS calls. No live account needed. |

Two AWS identities are used on purpose. `grc-lab-admin` builds the test
environment through Terraform. `grc-lab-readonly` runs the collector. The
identity that audits infrastructure shouldn't also be able to change it.

## Running it

```bash
# Stand up the test buckets (one time, needs an admin profile)
cd terraform
terraform init
terraform apply -var="aws_profile=grc-lab-admin"

# Run the collector (read-only profile)
cd ..
pip install -r requirements.txt
python evidence_collector.py

# Run the tests (no AWS needed)
python -m unittest test_evidence_collector.py -v
```

The collector writes three files: `evidence-output.json` (the full record),
`evidence-output.csv` (the summary an auditor would read), and `exceptions.csv`
(only the waived buckets and their documented reason).

Sample run:

```
grc-evidence-lab-sse-kms-cmk-...
  Encryption: encrypted (aws:kms, key: CUSTOMER)
  SOC 2 CC6.1:           PASS
  ISO 27001 A.8.24:      PASS
  NIST 800-53 SC-28(1):  PASS
```

## Something I ran into

AWS has applied SSE-S3 encryption to every new bucket by default since January
2023, and you can't turn it off. A bucket I created with no encryption config at
all still reports as encrypted.

That means SOC 2 and ISO's "no encryption" failure can't really happen in a
current AWS account. Those controls were written before the default changed. The
code still handles that case, but the only way to test it now is with a mocked
response, which is what one of the unit tests does. It also leaves NIST's
customer-managed-key requirement as the one bar that still takes deliberate work
to meet.

## Not done yet

- AWS only. Azure Storage encryption would be the equivalent for a later version.
- One control, done end to end, rather than many at a surface level.
- `grc-lab-readonly` uses a long-lived access key. A production setup would use
  short-lived role-based credentials instead.
