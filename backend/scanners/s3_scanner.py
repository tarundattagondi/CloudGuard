import os
import uuid

import boto3
from botocore.exceptions import ClientError

from models.findings import Finding, Severity, Status


def _is_demo_mode():
    return os.getenv("DEMO_MODE", "false").lower() == "true"


def _get_mock_findings():
    return [
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Bucket Public Access",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Bucket 'prod-app-assets' has Block Public Access settings disabled, allowing public ACLs and policies.",
            remediation="Enable all Block Public Access settings on the bucket via S3 console or CLI: aws s3api put-public-access-block --bucket prod-app-assets --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            nist_control="AC-3",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Bucket Public Access",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="Bucket 'internal-logs' has Block Public Access enabled.",
            remediation="No action required.",
            nist_control="AC-3",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Default Encryption",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Bucket 'dev-temp-uploads' does not have default server-side encryption enabled.",
            remediation="Enable default encryption on the bucket using AES-256 (SSE-S3) or AWS KMS: aws s3api put-bucket-encryption --bucket dev-temp-uploads --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
            nist_control="SC-13",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Default Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Bucket 'prod-app-assets' has default SSE-S3 encryption enabled.",
            remediation="No action required.",
            nist_control="SC-13",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Bucket Versioning",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="Bucket 'prod-app-assets' does not have versioning enabled, risking data loss from accidental deletions.",
            remediation="Enable versioning on the bucket: aws s3api put-bucket-versioning --bucket prod-app-assets --versioning-configuration Status=Enabled",
            nist_control="CP-9",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Access Logging",
            status=Status.FAIL,
            severity=Severity.LOW,
            description="Bucket 'dev-temp-uploads' does not have server access logging enabled.",
            remediation="Enable server access logging by setting a target bucket for log delivery: aws s3api put-bucket-logging --bucket dev-temp-uploads --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"my-log-bucket\",\"TargetPrefix\":\"dev-temp-uploads/\"}}'",
            nist_control="AU-2",
        ),
    ]


def _check_public_access(s3_client, bucket_name):
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        all_blocked = (
            config.get("BlockPublicAcls", False)
            and config.get("IgnorePublicAcls", False)
            and config.get("BlockPublicPolicy", False)
            and config.get("RestrictPublicBuckets", False)
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            all_blocked = False
        else:
            raise

    if all_blocked:
        return Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Bucket Public Access",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description=f"Bucket '{bucket_name}' has Block Public Access enabled.",
            remediation="No action required.",
            nist_control="AC-3",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="S3",
        check_name="S3 Bucket Public Access",
        status=Status.FAIL,
        severity=Severity.CRITICAL,
        description=f"Bucket '{bucket_name}' has Block Public Access settings disabled, allowing public ACLs and policies.",
        remediation=f"Enable all Block Public Access settings on the bucket: aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        nist_control="AC-3",
    )


def _check_encryption(s3_client, bucket_name):
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Default Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"Bucket '{bucket_name}' has default server-side encryption enabled.",
            remediation="No action required.",
            nist_control="SC-13",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return Finding(
                id=str(uuid.uuid4()),
                service="S3",
                check_name="S3 Default Encryption",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description=f"Bucket '{bucket_name}' does not have default server-side encryption enabled.",
                remediation=f"Enable default encryption using AES-256 or AWS KMS: aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                nist_control="SC-13",
            )
        raise


def _check_versioning(s3_client, bucket_name):
    response = s3_client.get_bucket_versioning(Bucket=bucket_name)
    status = response.get("Status", "Disabled")

    if status == "Enabled":
        return Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Bucket Versioning",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=f"Bucket '{bucket_name}' has versioning enabled.",
            remediation="No action required.",
            nist_control="CP-9",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="S3",
        check_name="S3 Bucket Versioning",
        status=Status.FAIL,
        severity=Severity.MEDIUM,
        description=f"Bucket '{bucket_name}' does not have versioning enabled, risking data loss from accidental deletions.",
        remediation=f"Enable versioning on the bucket: aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
        nist_control="CP-9",
    )


def _check_logging(s3_client, bucket_name):
    response = s3_client.get_bucket_logging(Bucket=bucket_name)

    if "LoggingEnabled" in response:
        return Finding(
            id=str(uuid.uuid4()),
            service="S3",
            check_name="S3 Access Logging",
            status=Status.PASS,
            severity=Severity.LOW,
            description=f"Bucket '{bucket_name}' has server access logging enabled.",
            remediation="No action required.",
            nist_control="AU-2",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="S3",
        check_name="S3 Access Logging",
        status=Status.FAIL,
        severity=Severity.LOW,
        description=f"Bucket '{bucket_name}' does not have server access logging enabled.",
        remediation=f"Enable server access logging by setting a target bucket: aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"your-log-bucket\",\"TargetPrefix\":\"{bucket_name}/\"}}}}'",
        nist_control="AU-2",
    )


def run_s3_scan():
    if _is_demo_mode():
        return _get_mock_findings()

    s3_client = boto3.client("s3")
    buckets = s3_client.list_buckets().get("Buckets", [])

    findings = []
    for bucket in buckets:
        name = bucket["Name"]
        findings.append(_check_public_access(s3_client, name))
        findings.append(_check_encryption(s3_client, name))
        findings.append(_check_versioning(s3_client, name))
        findings.append(_check_logging(s3_client, name))

    return findings
