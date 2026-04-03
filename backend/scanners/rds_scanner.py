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
            service="RDS",
            check_name="RDS Publicly Accessible",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="RDS instance 'prod-db-mysql' is publicly accessible. The instance can be reached from the internet if security groups allow it.",
            remediation="Disable public accessibility: aws rds modify-db-instance --db-instance-identifier prod-db-mysql --no-publicly-accessible --apply-immediately",
            nist_control="AC-3",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Publicly Accessible",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="RDS instance 'internal-postgres' is not publicly accessible.",
            remediation="No action required.",
            nist_control="AC-3",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Storage Encryption",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="RDS instance 'dev-db-postgres' does not have storage encryption enabled. Data at rest is unprotected.",
            remediation="Storage encryption cannot be enabled on an existing instance. Create an encrypted snapshot and restore from it: aws rds create-db-snapshot, then aws rds restore-db-instance-from-db-snapshot with --storage-encrypted.",
            nist_control="SC-28",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Automated Backups",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="RDS instance 'test-db' has automated backups disabled (retention period: 0 days).",
            remediation="Enable automated backups with a retention period: aws rds modify-db-instance --db-instance-identifier test-db --backup-retention-period 7 --apply-immediately",
            nist_control="CP-9",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Multi-AZ",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="RDS instance 'prod-db-mysql' is not configured for Multi-AZ deployment, leaving it vulnerable to availability zone failures.",
            remediation="Enable Multi-AZ: aws rds modify-db-instance --db-instance-identifier prod-db-mysql --multi-az --apply-immediately",
            nist_control="CP-10",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Multi-AZ",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="RDS instance 'internal-postgres' is configured for Multi-AZ deployment.",
            remediation="No action required.",
            nist_control="CP-10",
        ),
    ]


def _check_publicly_accessible(instance):
    db_id = instance["DBInstanceIdentifier"]
    if instance.get("PubliclyAccessible", False):
        return Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Publicly Accessible",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description=f"RDS instance '{db_id}' is publicly accessible. The instance can be reached from the internet if security groups allow it.",
            remediation=f"Disable public accessibility: aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately",
            nist_control="AC-3",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="RDS",
        check_name="RDS Publicly Accessible",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description=f"RDS instance '{db_id}' is not publicly accessible.",
        remediation="No action required.",
        nist_control="AC-3",
    )


def _check_storage_encryption(instance):
    db_id = instance["DBInstanceIdentifier"]
    if instance.get("StorageEncrypted", False):
        return Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Storage Encryption",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"RDS instance '{db_id}' has storage encryption enabled.",
            remediation="No action required.",
            nist_control="SC-28",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="RDS",
        check_name="RDS Storage Encryption",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description=f"RDS instance '{db_id}' does not have storage encryption enabled. Data at rest is unprotected.",
        remediation=f"Storage encryption cannot be enabled on an existing instance. Create an encrypted snapshot and restore from it: aws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-encrypted-snap, then restore with --storage-encrypted.",
        nist_control="SC-28",
    )


def _check_automated_backups(instance):
    db_id = instance["DBInstanceIdentifier"]
    retention = instance.get("BackupRetentionPeriod", 0)
    if retention > 0:
        return Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Automated Backups",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"RDS instance '{db_id}' has automated backups enabled (retention: {retention} days).",
            remediation="No action required.",
            nist_control="CP-9",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="RDS",
        check_name="RDS Automated Backups",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description=f"RDS instance '{db_id}' has automated backups disabled (retention period: 0 days).",
        remediation=f"Enable automated backups with a retention period: aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7 --apply-immediately",
        nist_control="CP-9",
    )


def _check_multi_az(instance):
    db_id = instance["DBInstanceIdentifier"]
    if instance.get("MultiAZ", False):
        return Finding(
            id=str(uuid.uuid4()),
            service="RDS",
            check_name="RDS Multi-AZ",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=f"RDS instance '{db_id}' is configured for Multi-AZ deployment.",
            remediation="No action required.",
            nist_control="CP-10",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="RDS",
        check_name="RDS Multi-AZ",
        status=Status.FAIL,
        severity=Severity.MEDIUM,
        description=f"RDS instance '{db_id}' is not configured for Multi-AZ deployment, leaving it vulnerable to availability zone failures.",
        remediation=f"Enable Multi-AZ: aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az --apply-immediately",
        nist_control="CP-10",
    )


def run_rds_scan():
    if _is_demo_mode():
        return _get_mock_findings()

    rds_client = boto3.client("rds")
    paginator = rds_client.get_paginator("describe_db_instances")

    findings = []
    for page in paginator.paginate():
        for instance in page["DBInstances"]:
            findings.append(_check_publicly_accessible(instance))
            findings.append(_check_storage_encryption(instance))
            findings.append(_check_automated_backups(instance))
            findings.append(_check_multi_az(instance))

    return findings
