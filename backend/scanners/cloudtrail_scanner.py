import os
import uuid

import boto3

from models.findings import Finding, Severity, Status


def _is_demo_mode():
    return os.getenv("DEMO_MODE", "false").lower() == "true"


def _get_mock_findings():
    return [
        Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Enabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="No CloudTrail trails are configured in this account. API activity is not being logged.",
            remediation="Create a CloudTrail trail: aws cloudtrail create-trail --name my-trail --s3-bucket-name my-trail-bucket --is-multi-region-trail && aws cloudtrail start-logging --name my-trail",
            nist_control="AU-2",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Multi-Region",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Trail 'prod-trail' is not configured for multi-region logging. Activity in other regions will not be captured.",
            remediation="Enable multi-region logging: aws cloudtrail update-trail --name prod-trail --is-multi-region-trail",
            nist_control="AU-2",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Log File Validation",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="Trail 'prod-trail' does not have log file validation enabled. Log tampering cannot be detected.",
            remediation="Enable log file validation: aws cloudtrail update-trail --name prod-trail --enable-log-file-validation",
            nist_control="AU-10",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Log Encryption",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Trail 'prod-trail' logs are not encrypted with a KMS key.",
            remediation="Enable SSE-KMS encryption: aws cloudtrail update-trail --name prod-trail --kms-key-id arn:aws:kms:us-east-1:123456789012:key/your-key-id",
            nist_control="SC-13",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Log Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Trail 'audit-trail' logs are encrypted with KMS.",
            remediation="No action required.",
            nist_control="SC-13",
        ),
    ]


def _check_trails_exist(trails):
    if not trails:
        return [Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Enabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="No CloudTrail trails are configured in this account. API activity is not being logged.",
            remediation="Create a CloudTrail trail: aws cloudtrail create-trail --name my-trail --s3-bucket-name my-trail-bucket --is-multi-region-trail && aws cloudtrail start-logging --name my-trail",
            nist_control="AU-2",
        )]
    return [Finding(
        id=str(uuid.uuid4()),
        service="CloudTrail",
        check_name="CloudTrail Enabled",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description=f"{len(trails)} CloudTrail trail(s) configured in this account.",
        remediation="No action required.",
        nist_control="AU-2",
    )]


def _check_multi_region(trail):
    name = trail["Name"]
    if trail.get("IsMultiRegionTrail", False):
        return Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Multi-Region",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"Trail '{name}' is configured for multi-region logging.",
            remediation="No action required.",
            nist_control="AU-2",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="CloudTrail",
        check_name="CloudTrail Multi-Region",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description=f"Trail '{name}' is not configured for multi-region logging. Activity in other regions will not be captured.",
        remediation=f"Enable multi-region logging: aws cloudtrail update-trail --name {name} --is-multi-region-trail",
        nist_control="AU-2",
    )


def _check_log_file_validation(trail):
    name = trail["Name"]
    if trail.get("LogFileValidationEnabled", False):
        return Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Log File Validation",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=f"Trail '{name}' has log file validation enabled.",
            remediation="No action required.",
            nist_control="AU-10",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="CloudTrail",
        check_name="CloudTrail Log File Validation",
        status=Status.FAIL,
        severity=Severity.MEDIUM,
        description=f"Trail '{name}' does not have log file validation enabled. Log tampering cannot be detected.",
        remediation=f"Enable log file validation: aws cloudtrail update-trail --name {name} --enable-log-file-validation",
        nist_control="AU-10",
    )


def _check_encryption(trail):
    name = trail["Name"]
    if trail.get("KmsKeyId"):
        return Finding(
            id=str(uuid.uuid4()),
            service="CloudTrail",
            check_name="CloudTrail Log Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"Trail '{name}' logs are encrypted with KMS.",
            remediation="No action required.",
            nist_control="SC-13",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="CloudTrail",
        check_name="CloudTrail Log Encryption",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description=f"Trail '{name}' logs are not encrypted with a KMS key.",
        remediation=f"Enable SSE-KMS encryption: aws cloudtrail update-trail --name {name} --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/YOUR-KEY-ID",
        nist_control="SC-13",
    )


def run_cloudtrail_scan():
    if _is_demo_mode():
        return _get_mock_findings()

    ct_client = boto3.client("cloudtrail")
    trails = ct_client.describe_trails().get("trailList", [])

    findings = _check_trails_exist(trails)

    for trail in trails:
        findings.append(_check_multi_region(trail))
        findings.append(_check_log_file_validation(trail))
        findings.append(_check_encryption(trail))

    return findings
