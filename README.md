# Cloud control crosswalk

Map one cloud security control to several compliance frameworks from a single
piece of evidence, instead of checking each framework separately. This lab does
it for AWS S3 encryption at rest, graded against SOC 2 CC6.1, ISO 27001 A.8.24,
and NIST 800-53 SC-28(1).

**Visual overview:** https://dev-kfarmer.github.io/grc-cloud-control-crosswalk/visual-overview.html
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

# FUTURE IMPROVEMENT
    # This loads a long-lived IAM user access key from the local AWS profile.
    # That key never expires, so if it leaks it works forever until someone
    # notices and manually revokes it.
    #
    # The fix is to stop using a permanent identity:
    #   Better - assume an IAM role via STS, which issues temporary credentials
    #            that expire in about an hour instead of a permanent key.
    #   Best   - use a workload identity with no stored secret at all, such as
    #            GitHub Actions via OIDC or an EC2 instance profile, so there is
    #            no long-lived credential anywhere to leak.
    #
    # A role also improves the evidence itself: each run assumes the role with
    # its own session name, so CloudTrail shows which run made which call,
    # instead of every run looking like the same shared user.
## DOCKER Running in a container

The collector ships as a container image — the script plus everything it needs to run,
in one sealed unit. How that unit is built is itself a set of security decisions:

| Build decision | Why it matters | Control |
|---|---|---|
| Minimal base image — no shell, no package manager | An attacker who gets in has no tools to work with, and nothing new can be installed | NIST 800-53 CM-7 |
| Build tools stay in a separate stage | Only the interpreter, dependencies, and app code ship | NIST 800-53 CM-7 |
| Runs as a normal user, not root | A compromised process can't reconfigure the container | NIST 800-53 AC-6 · SOC 2 CC6.1 |
| No credentials in the image | AWS identity is mounted read-only at run time; the image alone grants no access | NIST 800-53 IA-5 |

**47.2 MB**, versus roughly 1 GB for a standard `python:3.12` base — about 95% less
software that could be attacked.

### Build and run

    docker build -t grc-evidence-collector .
    docker run --rm -v "${HOME}/.aws:/home/nonroot/.aws:ro" grc-evidence-collector

### Known limitations

- Read-only root filesystem and dropped capabilities are runtime settings, not Dockerfile
  directives. They belong in a Kubernetes pod spec — next phase of this lab.
- Output is written to the container's working directory, which is ephemeral. The path
  should be configurable before this runs on a schedule.
- Identity is still a long-lived IAM user key mounted from the host. The production path
  is a task role via STS. Documented bootstrap exception, not a recommendation.

Control mappings are deliberately narrow. Claiming broad coverage for a Dockerfile would
repeat the problem this lab exists to expose: an assertion that sounds strong and tests
nothing.
