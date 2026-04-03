import os
import uuid

import boto3

from models.findings import Finding, Severity, Status

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
}


def _is_demo_mode():
    return os.getenv("DEMO_MODE", "false").lower() == "true"


def _get_mock_findings():
    return [
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group SSH Open",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Security group 'sg-0a1b2c3d (web-servers)' allows SSH (port 22) inbound from 0.0.0.0/0.",
            remediation="Restrict SSH access to specific IP ranges: aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d --protocol tcp --port 22 --cidr 0.0.0.0/0, then add your trusted CIDR.",
            nist_control="SC-7",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group RDP Open",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Security group 'sg-4e5f6a7b (windows-prod)' allows RDP (port 3389) inbound from 0.0.0.0/0.",
            remediation="Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager for remote access instead of exposing RDP publicly.",
            nist_control="SC-7",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group All Traffic Open",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Security group 'sg-8c9d0e1f (legacy-app)' allows all inbound traffic (all ports, all protocols) from 0.0.0.0/0.",
            remediation="Remove the unrestricted inbound rule and replace with specific port/protocol rules that match actual application requirements.",
            nist_control="SC-7",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group Database Port Open",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Security group 'sg-2a3b4c5d (data-tier)' allows PostgreSQL (port 5432) inbound from 0.0.0.0/0.",
            remediation="Restrict database access to application-tier security groups only. Databases should never be directly accessible from the internet.",
            nist_control="SC-7",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group Unrestricted Egress",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="Security group 'sg-6e7f8a9b (internal-services)' allows all outbound traffic to 0.0.0.0/0.",
            remediation="Restrict egress to only required destinations and ports. Limiting outbound traffic reduces the blast radius of a compromised instance and prevents data exfiltration.",
            nist_control="SC-7",
        ),
        Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group SSH Open",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="Security group 'sg-1f2e3d4c (api-servers)' does not allow SSH from 0.0.0.0/0.",
            remediation="No action required.",
            nist_control="SC-7",
        ),
    ]


def _sg_label(sg):
    return f"{sg['GroupId']} ({sg.get('GroupName', 'unnamed')})"


def _rule_allows_open_cidr(rule):
    for ip_range in rule.get("IpRanges", []):
        if ip_range.get("CidrIp") in OPEN_CIDRS:
            return True
    for ip_range in rule.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") in OPEN_CIDRS:
            return True
    return False


def _rule_covers_port(rule, port):
    from_port = rule.get("FromPort", -1)
    to_port = rule.get("ToPort", -1)
    # -1 means all traffic (protocol -1)
    if rule.get("IpProtocol") == "-1":
        return True
    return from_port <= port <= to_port


def _check_ssh_open(sg):
    label = _sg_label(sg)
    for rule in sg.get("IpPermissions", []):
        if _rule_allows_open_cidr(rule) and _rule_covers_port(rule, 22):
            return Finding(
                id=str(uuid.uuid4()),
                service="EC2",
                check_name="Security Group SSH Open",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description=f"Security group '{label}' allows SSH (port 22) inbound from 0.0.0.0/0.",
                remediation=f"Restrict SSH access to specific IP ranges: aws ec2 revoke-security-group-ingress --group-id {sg['GroupId']} --protocol tcp --port 22 --cidr 0.0.0.0/0, then add your trusted CIDR.",
                nist_control="SC-7",
            )
    return Finding(
        id=str(uuid.uuid4()),
        service="EC2",
        check_name="Security Group SSH Open",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description=f"Security group '{label}' does not allow SSH from 0.0.0.0/0.",
        remediation="No action required.",
        nist_control="SC-7",
    )


def _check_rdp_open(sg):
    label = _sg_label(sg)
    for rule in sg.get("IpPermissions", []):
        if _rule_allows_open_cidr(rule) and _rule_covers_port(rule, 3389):
            return Finding(
                id=str(uuid.uuid4()),
                service="EC2",
                check_name="Security Group RDP Open",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description=f"Security group '{label}' allows RDP (port 3389) inbound from 0.0.0.0/0.",
                remediation=f"Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager for remote access: aws ec2 revoke-security-group-ingress --group-id {sg['GroupId']} --protocol tcp --port 3389 --cidr 0.0.0.0/0",
                nist_control="SC-7",
            )
    return Finding(
        id=str(uuid.uuid4()),
        service="EC2",
        check_name="Security Group RDP Open",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description=f"Security group '{label}' does not allow RDP from 0.0.0.0/0.",
        remediation="No action required.",
        nist_control="SC-7",
    )


def _check_all_traffic_open(sg):
    label = _sg_label(sg)
    for rule in sg.get("IpPermissions", []):
        if rule.get("IpProtocol") == "-1" and _rule_allows_open_cidr(rule):
            return Finding(
                id=str(uuid.uuid4()),
                service="EC2",
                check_name="Security Group All Traffic Open",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description=f"Security group '{label}' allows all inbound traffic (all ports, all protocols) from 0.0.0.0/0.",
                remediation=f"Remove the unrestricted inbound rule and replace with specific port/protocol rules: aws ec2 revoke-security-group-ingress --group-id {sg['GroupId']} --protocol -1 --cidr 0.0.0.0/0",
                nist_control="SC-7",
            )
    return Finding(
        id=str(uuid.uuid4()),
        service="EC2",
        check_name="Security Group All Traffic Open",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description=f"Security group '{label}' does not allow all inbound traffic from 0.0.0.0/0.",
        remediation="No action required.",
        nist_control="SC-7",
    )


def _check_db_ports_open(sg):
    findings = []
    label = _sg_label(sg)

    for rule in sg.get("IpPermissions", []):
        if not _rule_allows_open_cidr(rule):
            continue
        for port, db_name in DB_PORTS.items():
            if _rule_covers_port(rule, port):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    service="EC2",
                    check_name="Security Group Database Port Open",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description=f"Security group '{label}' allows {db_name} (port {port}) inbound from 0.0.0.0/0.",
                    remediation=f"Restrict {db_name} access to application-tier security groups only. Databases should never be directly accessible from the internet: aws ec2 revoke-security-group-ingress --group-id {sg['GroupId']} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                    nist_control="SC-7",
                ))

    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            service="EC2",
            check_name="Security Group Database Port Open",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=f"Security group '{label}' does not expose database ports to 0.0.0.0/0.",
            remediation="No action required.",
            nist_control="SC-7",
        ))

    return findings


def _check_unrestricted_egress(sg):
    label = _sg_label(sg)
    for rule in sg.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol") == "-1" and _rule_allows_open_cidr(rule):
            return Finding(
                id=str(uuid.uuid4()),
                service="EC2",
                check_name="Security Group Unrestricted Egress",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                description=f"Security group '{label}' allows all outbound traffic to 0.0.0.0/0.",
                remediation=f"Restrict egress to only required destinations and ports to reduce blast radius of a compromised instance: aws ec2 revoke-security-group-egress --group-id {sg['GroupId']} --protocol -1 --cidr 0.0.0.0/0",
                nist_control="SC-7",
            )
    return Finding(
        id=str(uuid.uuid4()),
        service="EC2",
        check_name="Security Group Unrestricted Egress",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        description=f"Security group '{label}' restricts outbound traffic.",
        remediation="No action required.",
        nist_control="SC-7",
    )


def run_sg_scan():
    if _is_demo_mode():
        return _get_mock_findings()

    ec2_client = boto3.client("ec2")
    paginator = ec2_client.get_paginator("describe_security_groups")

    findings = []
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            findings.append(_check_ssh_open(sg))
            findings.append(_check_rdp_open(sg))
            findings.append(_check_all_traffic_open(sg))
            findings.extend(_check_db_ports_open(sg))
            findings.append(_check_unrestricted_egress(sg))

    return findings
