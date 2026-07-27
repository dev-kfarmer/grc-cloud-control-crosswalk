"""
S3 encryption-at-rest evidence collector (control UC-04).

For every S3 bucket in the account, collects ONE normalized evidence object
(schema defined in control-spec.md), then grades that single object against
three compliance frameworks: SOC 2 CC6.1, ISO 27001 A.8.24, NIST 800-53
SC-28(1). This is the "assess once, comply with many" pattern -- evidence is
collected once per bucket, never re-fetched per framework.

Run with the read-only 'grc-lab' AWS CLI profile:
    python evidence_collector.py
"""

import csv
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

AWS_PROFILE = "grc-lab"


def get_bucket_region(s3_client, bucket_name):
    """GetBucketLocation returns None for us-east-1 instead of the string -- normalize it."""
    response = s3_client.get_bucket_location(Bucket=bucket_name)
    return response.get("LocationConstraint") or "us-east-1"


def get_encryption_config(s3_client, bucket_name):
    """
    Returns (encryption_enabled, sse_algorithm, kms_key_arn).

    An unencrypted bucket makes GetBucketEncryption raise an error rather than
    return a false-y value. Catching ONLY that specific error code matters: a
    bare except here would also swallow real failures (bad credentials,
    throttling) and misreport them as "unencrypted" -- the false-negative
    control-spec.md calls out as the top audit risk for this control.
    """
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as error:
        if error.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False, None, None
        raise

    rule = response["ServerSideEncryptionConfiguration"]["Rules"][0]
    default = rule["ApplyServerSideEncryptionByDefault"]
    sse_algorithm = default["SSEAlgorithm"]
    kms_key_arn = default.get("KMSMasterKeyID")
    return True, sse_algorithm, kms_key_arn


def get_kms_key_manager(kms_client, kms_key_arn):
    """Resolves whether a KMS key is AWS-owned or customer-owned -- the fact NIST SC-28(1) cares about."""
    response = kms_client.describe_key(KeyId=kms_key_arn)
    return response["KeyMetadata"]["KeyManager"]  # "AWS" or "CUSTOMER"


def get_exception_tags(s3_client, bucket_name):
    """
    Returns (is_tagged_exception, exception_reason).

    Per control-spec.md: a bucket tagged compliance-exception=true WITHOUT an
    exception_reason tag is an undocumented exception, which must still FAIL
    -- it is not waived just because someone added one tag.
    """
    try:
        response = s3_client.get_bucket_tagging(Bucket=bucket_name)
    except ClientError as error:
        if error.response["Error"]["Code"] == "NoSuchTagSet":
            return False, None
        raise

    tags = {tag["Key"]: tag["Value"] for tag in response["TagSet"]}
    is_tagged_exception = tags.get("compliance-exception") == "true"
    exception_reason = tags.get("exception_reason")
    return is_tagged_exception, exception_reason


def build_evidence(s3_client, kms_client, bucket_name):
    """Collects one normalized evidence object for a bucket, matching the schema in control-spec.md."""
    region = get_bucket_region(s3_client, bucket_name)
    encryption_enabled, sse_algorithm, kms_key_arn = get_encryption_config(s3_client, bucket_name)

    kms_key_manager = None
    if sse_algorithm == "aws:kms" and kms_key_arn:
        kms_key_manager = get_kms_key_manager(kms_client, kms_key_arn)

    is_tagged_exception, exception_reason = get_exception_tags(s3_client, bucket_name)
    is_waived = is_tagged_exception and bool(exception_reason)

    return {
        "control_id": "UC-04",
        "resource_type": "s3_bucket",
        "resource_id": bucket_name,
        "region": region,
        "evidence_timestamp": datetime.now(timezone.utc).isoformat(),
        "encryption_enabled": encryption_enabled,
        "sse_algorithm": sse_algorithm,
        "kms_key_manager": kms_key_manager,
        "is_waived": is_waived,
        "exception_reason": exception_reason,
        "undocumented_exception_tag": is_tagged_exception and not exception_reason,
    }


def evaluate_frameworks(evidence):
    """
    Grades ONE evidence object against all three frameworks -- no new API
    calls here, just three different pass bars applied to data already
    collected. This function is the "assess once, comply with many" step.
    """
    if evidence["is_waived"]:
        return {
            "soc2_cc6_1": "WAIVED",
            "iso_27001_a8_24": "WAIVED",
            "nist_800_53_sc28_1": "WAIVED",
        }

    soc2_iso_verdict = "PASS" if evidence["encryption_enabled"] else "FAIL"

    nist_pass = (
        evidence["sse_algorithm"] == "aws:kms"
        and evidence["kms_key_manager"] == "CUSTOMER"
    )
    nist_verdict = "PASS" if nist_pass else "FAIL"

    return {
        "soc2_cc6_1": soc2_iso_verdict,
        "iso_27001_a8_24": soc2_iso_verdict,
        "nist_800_53_sc28_1": nist_verdict,
    }


def print_summary(bucket_name, evidence, framework_results):
    print(f"\n{bucket_name}")
    if evidence["undocumented_exception_tag"]:
        print("  WARNING: compliance-exception tag present with no exception_reason -- treated as FAIL, not waived")
    if evidence["encryption_enabled"]:
        status = f"encrypted ({evidence['sse_algorithm']}, key: {evidence['kms_key_manager']})"
    else:
        status = "NOT ENCRYPTED"
    print(f"  Encryption: {status}")
    print(f"  SOC 2 CC6.1:           {framework_results['soc2_cc6_1']}")
    print(f"  ISO 27001 A.8.24:      {framework_results['iso_27001_a8_24']}")
    print(f"  NIST 800-53 SC-28(1):  {framework_results['nist_800_53_sc28_1']}")


CSV_COLUMNS = [
    "bucket_name",
    "region",
    "evidence_timestamp",
    "encryption_enabled",
    "sse_algorithm",
    "kms_key_manager",
    "soc2_cc6_1",
    "iso_27001_a8_24",
    "nist_800_53_sc28_1",
    "waived",
    "exception_reason",
]


def write_csv(results, path):
    """
    Auditor-facing summary: one row per bucket, one column per framework
    verdict. The JSON output stays the full evidence record (including raw
    API responses); this is the flattened version you'd actually hand
    someone for review.
    """
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for result in results:
            evidence = result["evidence"]
            verdicts = result["framework_results"]
            writer.writerow({
                "bucket_name": evidence["resource_id"],
                "region": evidence["region"],
                "evidence_timestamp": evidence["evidence_timestamp"],
                "encryption_enabled": evidence["encryption_enabled"],
                "sse_algorithm": evidence["sse_algorithm"],
                "kms_key_manager": evidence["kms_key_manager"],
                "soc2_cc6_1": verdicts["soc2_cc6_1"],
                "iso_27001_a8_24": verdicts["iso_27001_a8_24"],
                "nist_800_53_sc28_1": verdicts["nist_800_53_sc28_1"],
                "waived": evidence["is_waived"],
                "exception_reason": evidence["exception_reason"] or "",
            })


EXCEPTION_COLUMNS = [
    "resource",
    "region",
    "status",
    "exception_reason",
    "evidence_timestamp",
]


def write_exceptions_csv(results, path):
    """
    Standalone exception register: only the buckets that were WAIVED, with
    their documented reason. This is the "here is what we have formally
    accepted the risk on" artifact, kept separate from the full report --
    the thing an auditor asks to see when they spot a waived item.

    Undocumented exceptions (tagged but with no reason) are deliberately NOT
    here -- they stay in the main report as a FAIL, because an undocumented
    exception is not a waiver.
    """
    waived = [r for r in results if r["evidence"]["is_waived"]]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EXCEPTION_COLUMNS)
        writer.writeheader()
        for result in waived:
            evidence = result["evidence"]
            writer.writerow({
                "resource": evidence["resource_id"],
                "region": evidence["region"],
                "status": "WAIVED",
                "exception_reason": evidence["exception_reason"] or "",
                "evidence_timestamp": evidence["evidence_timestamp"],
            })


def write_json(results, path):
    """Full evidence record, including everything collected -- the audit trail."""
    with open(path, "w") as f:
        json.dump(results, f, indent=2)


def save_output(path, write_fn):
    """
    Writes an output file, but reports a clear message instead of a raw
    traceback if the file can't be written. The most common cause on Windows
    is the file being open in Excel, which locks it. This keeps one locked
    file from crashing the whole run -- the outputs that can be written still
    are.
    """
    try:
        write_fn(path)
        print(f"Wrote {path}")
    except PermissionError:
        print(
            f"WARNING: could not write {path} -- is it open in another program "
            f"(e.g. Excel)? Close it and re-run. Other outputs were still written."
        )


def main():
    session = boto3.Session(profile_name=AWS_PROFILE)
    s3_client = session.client("s3")
    kms_client = session.client("kms")

    buckets = s3_client.list_buckets()["Buckets"]
    results = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        evidence = build_evidence(s3_client, kms_client, bucket_name)
        framework_results = evaluate_frameworks(evidence)
        print_summary(bucket_name, evidence, framework_results)
        results.append({"evidence": evidence, "framework_results": framework_results})

    print()
    save_output("evidence-output.json", lambda path: write_json(results, path))
    save_output("evidence-output.csv", lambda path: write_csv(results, path))
    save_output("exceptions.csv", lambda path: write_exceptions_csv(results, path))


if __name__ == "__main__":
    main()
