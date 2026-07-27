"""
Unit tests for evidence_collector.py -- no AWS calls, everything mocked.

Covers the two edge cases control-spec.md explicitly flags as the highest
audit risk for this control:
  1. An unencrypted bucket must FAIL, not be silently skipped (the API
     raises an error instead of returning a false-y value).
  2. A "compliance-exception=true" tag with no exception_reason is an
     undocumented exception and must still FAIL, not be waived.

Run with:
    python -m unittest test_evidence_collector.py
"""

import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from evidence_collector import build_evidence, evaluate_frameworks, get_encryption_config


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "TestOperation")


class TestGetEncryptionConfig(unittest.TestCase):
    def test_missing_encryption_config_is_reported_as_disabled_not_skipped(self):
        s3_client = MagicMock()
        s3_client.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )

        encryption_enabled, sse_algorithm, kms_key_arn = get_encryption_config(s3_client, "some-bucket")

        self.assertFalse(encryption_enabled)
        self.assertIsNone(sse_algorithm)
        self.assertIsNone(kms_key_arn)

    def test_unrelated_api_errors_are_not_swallowed(self):
        s3_client = MagicMock()
        s3_client.get_bucket_encryption.side_effect = client_error("AccessDenied")

        with self.assertRaises(ClientError):
            get_encryption_config(s3_client, "some-bucket")


class TestBuildEvidenceAndFrameworkVerdicts(unittest.TestCase):
    def _mock_clients(self, encryption_response=None, encryption_error=None, tags=None, kms_key_manager=None):
        s3_client = MagicMock()
        s3_client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

        if encryption_error:
            s3_client.get_bucket_encryption.side_effect = client_error(encryption_error)
        else:
            s3_client.get_bucket_encryption.return_value = encryption_response

        if tags:
            s3_client.get_bucket_tagging.return_value = {
                "TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]
            }
        else:
            s3_client.get_bucket_tagging.side_effect = client_error("NoSuchTagSet")

        kms_client = MagicMock()
        if kms_key_manager:
            kms_client.describe_key.return_value = {"KeyMetadata": {"KeyManager": kms_key_manager}}

        return s3_client, kms_client

    def test_unencrypted_bucket_fails_all_frameworks(self):
        s3_client, kms_client = self._mock_clients(
            encryption_error="ServerSideEncryptionConfigurationNotFoundError"
        )

        evidence = build_evidence(s3_client, kms_client, "unencrypted-bucket")
        results = evaluate_frameworks(evidence)

        self.assertFalse(evidence["encryption_enabled"])
        self.assertEqual(results["soc2_cc6_1"], "FAIL")
        self.assertEqual(results["iso_27001_a8_24"], "FAIL")
        self.assertEqual(results["nist_800_53_sc28_1"], "FAIL")

    def test_sse_s3_passes_soc2_iso_but_fails_nist(self):
        s3_client, kms_client = self._mock_clients(
            encryption_response={
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            }
        )

        evidence = build_evidence(s3_client, kms_client, "sse-s3-bucket")
        results = evaluate_frameworks(evidence)

        self.assertEqual(results["soc2_cc6_1"], "PASS")
        self.assertEqual(results["iso_27001_a8_24"], "PASS")
        self.assertEqual(results["nist_800_53_sc28_1"], "FAIL")

    def test_kms_aws_managed_key_fails_nist(self):
        s3_client, kms_client = self._mock_clients(
            encryption_response={
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/aws-owned",
                        }
                    }]
                }
            },
            kms_key_manager="AWS",
        )

        evidence = build_evidence(s3_client, kms_client, "kms-aws-managed-bucket")
        results = evaluate_frameworks(evidence)

        self.assertEqual(results["soc2_cc6_1"], "PASS")
        self.assertEqual(results["nist_800_53_sc28_1"], "FAIL")

    def test_kms_customer_managed_key_passes_all_frameworks(self):
        s3_client, kms_client = self._mock_clients(
            encryption_response={
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/customer-owned",
                        }
                    }]
                }
            },
            kms_key_manager="CUSTOMER",
        )

        evidence = build_evidence(s3_client, kms_client, "kms-customer-managed-bucket")
        results = evaluate_frameworks(evidence)

        self.assertEqual(results["soc2_cc6_1"], "PASS")
        self.assertEqual(results["iso_27001_a8_24"], "PASS")
        self.assertEqual(results["nist_800_53_sc28_1"], "PASS")

    def test_undocumented_exception_tag_still_fails_not_waived(self):
        s3_client, kms_client = self._mock_clients(
            encryption_error="ServerSideEncryptionConfigurationNotFoundError",
            tags={"compliance-exception": "true"},  # no exception_reason tag
        )

        evidence = build_evidence(s3_client, kms_client, "undocumented-exception-bucket")
        results = evaluate_frameworks(evidence)

        self.assertTrue(evidence["undocumented_exception_tag"])
        self.assertFalse(evidence["is_waived"])
        self.assertEqual(results["soc2_cc6_1"], "FAIL")
        self.assertEqual(results["nist_800_53_sc28_1"], "FAIL")

    def test_documented_exception_is_waived_on_all_frameworks(self):
        s3_client, kms_client = self._mock_clients(
            encryption_error="ServerSideEncryptionConfigurationNotFoundError",
            tags={
                "compliance-exception": "true",
                "exception_reason": "Legacy migration bucket - decommission scheduled Q3 - tracked in JIRA-1234",
            },
        )

        evidence = build_evidence(s3_client, kms_client, "documented-exception-bucket")
        results = evaluate_frameworks(evidence)

        self.assertFalse(evidence["undocumented_exception_tag"])
        self.assertTrue(evidence["is_waived"])
        self.assertEqual(results["soc2_cc6_1"], "WAIVED")
        self.assertEqual(results["iso_27001_a8_24"], "WAIVED")
        self.assertEqual(results["nist_800_53_sc28_1"], "WAIVED")


if __name__ == "__main__":
    unittest.main()
