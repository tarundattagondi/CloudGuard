import json
import os
import uuid
from datetime import datetime, timezone

import boto3

from models.findings import Finding, Severity, Status

MAX_KEY_AGE_DAYS = 90
MAX_INACTIVE_DAYS = 90


def _is_demo_mode():
    return os.getenv("DEMO_MODE", "false").lower() == "true"


def _get_mock_findings():
    return [
        # MFA checks
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM User MFA Enabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="IAM user 'dev-john' does not have MFA enabled.",
            remediation="Enable MFA for this user: Go to IAM console > Users > dev-john > Security credentials > Assign MFA device, or use CLI: aws iam enable-mfa-device",
            nist_control="IA-2",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM User MFA Enabled",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="IAM user 'admin-sarah' has MFA enabled.",
            remediation="No action required.",
            nist_control="IA-2",
        ),
        # Overly permissive policy checks
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM Overly Permissive Policy",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="IAM policy 'LegacyAdminAccess' grants full access (Action: *, Resource: *), violating least-privilege.",
            remediation="Replace the wildcard policy with scoped permissions that grant only the access required. Review AWS Access Analyzer findings to identify actually-used permissions, then create a least-privilege policy.",
            nist_control="AC-6",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM Overly Permissive Policy",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="IAM policy 'S3ReadOnlyAccess' follows least-privilege principles.",
            remediation="No action required.",
            nist_control="AC-6",
        ),
        # Access key age checks
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM Access Key Age",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="IAM user 'svc-deployer' has an access key (AKIA...3XQP) that is 147 days old, exceeding the 90-day rotation policy.",
            remediation="Rotate the access key: 1) Create a new key with aws iam create-access-key --user-name svc-deployer, 2) Update all applications using the old key, 3) Deactivate and delete the old key with aws iam delete-access-key",
            nist_control="IA-5",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM Access Key Age",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="IAM user 'admin-sarah' has access keys within the 90-day rotation window.",
            remediation="No action required.",
            nist_control="IA-5",
        ),
        # Inactive user checks
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="IAM Inactive User",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="IAM user 'former-contractor' has not logged in for 213 days but the account is still active.",
            remediation="Disable the inactive account: 1) Deactivate access keys with aws iam update-access-key --status Inactive, 2) Remove console access with aws iam delete-login-profile --user-name former-contractor, 3) Review and remove from all groups.",
            nist_control="AC-2",
        ),
        # Root access key checks
        Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="Root Account Access Keys",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="The root account has active access keys. Root access keys provide unrestricted access and cannot be scoped with policies.",
            remediation="Delete root account access keys immediately: Sign in as root > IAM console > Security credentials > Access keys > Delete. Use IAM users or roles for programmatic access instead.",
            nist_control="AC-6",
        ),
    ]


def _check_mfa(iam_client):
    findings = []
    users = iam_client.list_users().get("Users", [])

    for user in users:
        username = user["UserName"]
        mfa_devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])

        if mfa_devices:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                service="IAM",
                check_name="IAM User MFA Enabled",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                description=f"IAM user '{username}' has MFA enabled.",
                remediation="No action required.",
                nist_control="IA-2",
            ))
        else:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                service="IAM",
                check_name="IAM User MFA Enabled",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description=f"IAM user '{username}' does not have MFA enabled.",
                remediation=f"Enable MFA for this user: Go to IAM console > Users > {username} > Security credentials > Assign MFA device, or use CLI: aws iam enable-mfa-device",
                nist_control="IA-2",
            ))

    return findings


def _check_overly_permissive_policies(iam_client):
    findings = []
    paginator = iam_client.get_paginator("list_policies")

    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            version_id = policy["DefaultVersionId"]

            version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            document = version["PolicyVersion"]["Document"]
            if isinstance(document, str):
                document = json.loads(document)

            statements = document.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            is_overly_permissive = False
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions and "*" in resources:
                    is_overly_permissive = True
                    break

            if is_overly_permissive:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    service="IAM",
                    check_name="IAM Overly Permissive Policy",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description=f"IAM policy '{policy_name}' grants full access (Action: *, Resource: *), violating least-privilege.",
                    remediation=f"Replace the wildcard policy '{policy_name}' with scoped permissions that grant only the access required. Review AWS Access Analyzer findings to identify actually-used permissions, then create a least-privilege policy.",
                    nist_control="AC-6",
                ))
            else:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    service="IAM",
                    check_name="IAM Overly Permissive Policy",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    description=f"IAM policy '{policy_name}' follows least-privilege principles.",
                    remediation="No action required.",
                    nist_control="AC-6",
                ))

    return findings


def _check_access_key_age(iam_client):
    findings = []
    now = datetime.now(timezone.utc)
    users = iam_client.list_users().get("Users", [])

    for user in users:
        username = user["UserName"]
        keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

        for key in keys:
            if key["Status"] != "Active":
                continue

            key_id = key["AccessKeyId"]
            created = key["CreateDate"]
            age_days = (now - created).days

            if age_days > MAX_KEY_AGE_DAYS:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    service="IAM",
                    check_name="IAM Access Key Age",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"IAM user '{username}' has an access key ({key_id[:4]}...{key_id[-4:]}) that is {age_days} days old, exceeding the {MAX_KEY_AGE_DAYS}-day rotation policy.",
                    remediation=f"Rotate the access key: 1) Create a new key with aws iam create-access-key --user-name {username}, 2) Update all applications using the old key, 3) Deactivate and delete the old key with aws iam delete-access-key",
                    nist_control="IA-5",
                ))
            else:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    service="IAM",
                    check_name="IAM Access Key Age",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    description=f"IAM user '{username}' has access key ({key_id[:4]}...{key_id[-4:]}) within the {MAX_KEY_AGE_DAYS}-day rotation window ({age_days} days old).",
                    remediation="No action required.",
                    nist_control="IA-5",
                ))

    return findings


def _check_inactive_users(iam_client):
    findings = []
    now = datetime.now(timezone.utc)
    users = iam_client.list_users().get("Users", [])

    for user in users:
        username = user["UserName"]
        password_last_used = user.get("PasswordLastUsed")

        if password_last_used is None:
            continue

        days_since_login = (now - password_last_used).days

        if days_since_login > MAX_INACTIVE_DAYS:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                service="IAM",
                check_name="IAM Inactive User",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                description=f"IAM user '{username}' has not logged in for {days_since_login} days but the account is still active.",
                remediation=f"Disable the inactive account: 1) Deactivate access keys with aws iam update-access-key --status Inactive, 2) Remove console access with aws iam delete-login-profile --user-name {username}, 3) Review and remove from all groups.",
                nist_control="AC-2",
            ))
        else:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                service="IAM",
                check_name="IAM Inactive User",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                description=f"IAM user '{username}' last logged in {days_since_login} days ago.",
                remediation="No action required.",
                nist_control="AC-2",
            ))

    return findings


def _check_root_access_keys(iam_client):
    summary = iam_client.get_account_summary().get("SummaryMap", {})
    root_keys = summary.get("AccountAccessKeysPresent", 0)

    if root_keys > 0:
        return Finding(
            id=str(uuid.uuid4()),
            service="IAM",
            check_name="Root Account Access Keys",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="The root account has active access keys. Root access keys provide unrestricted access and cannot be scoped with policies.",
            remediation="Delete root account access keys immediately: Sign in as root > IAM console > Security credentials > Access keys > Delete. Use IAM users or roles for programmatic access instead.",
            nist_control="AC-6",
        )
    return Finding(
        id=str(uuid.uuid4()),
        service="IAM",
        check_name="Root Account Access Keys",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description="The root account does not have active access keys.",
        remediation="No action required.",
        nist_control="AC-6",
    )


def run_iam_scan():
    if _is_demo_mode():
        return _get_mock_findings()

    iam_client = boto3.client("iam")

    findings = []
    findings.extend(_check_mfa(iam_client))
    findings.extend(_check_overly_permissive_policies(iam_client))
    findings.extend(_check_access_key_age(iam_client))
    findings.extend(_check_inactive_users(iam_client))
    findings.append(_check_root_access_keys(iam_client))

    return findings
