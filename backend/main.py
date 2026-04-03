from dataclasses import asdict
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models.findings import Severity, Status
from scanners.s3_scanner import run_s3_scan
from scanners.iam_scanner import run_iam_scan
from scanners.sg_scanner import run_sg_scan
from scanners.cloudtrail_scanner import run_cloudtrail_scan
from scanners.rds_scanner import run_rds_scan

app = FastAPI(title="CloudGuard", description="AWS Security Misconfiguration Scanner & Risk Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANNERS = {
    "s3": run_s3_scan,
    "iam": run_iam_scan,
    "sg": run_sg_scan,
    "cloudtrail": run_cloudtrail_scan,
    "rds": run_rds_scan,
}

NIST_CONTROLS = {
    "AC-2": {
        "id": "AC-2",
        "family": "Access Control",
        "name": "Account Management",
        "description": "Manage information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
    },
    "AC-3": {
        "id": "AC-3",
        "family": "Access Control",
        "name": "Access Enforcement",
        "description": "Enforce approved authorizations for logical access to information and system resources.",
    },
    "AC-6": {
        "id": "AC-6",
        "family": "Access Control",
        "name": "Least Privilege",
        "description": "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.",
    },
    "AU-2": {
        "id": "AU-2",
        "family": "Audit and Accountability",
        "name": "Audit Events",
        "description": "Identify events that the system must be capable of auditing and coordinate the audit function with other organizational entities.",
    },
    "AU-10": {
        "id": "AU-10",
        "family": "Audit and Accountability",
        "name": "Non-repudiation",
        "description": "Provide irrefutable evidence that an action occurred, protecting against false denial of having performed an action.",
    },
    "CP-9": {
        "id": "CP-9",
        "family": "Contingency Planning",
        "name": "Information System Backup",
        "description": "Conduct backups of user-level and system-level information at defined frequency.",
    },
    "CP-10": {
        "id": "CP-10",
        "family": "Contingency Planning",
        "name": "Information System Recovery and Reconstitution",
        "description": "Provide for the recovery and reconstitution of the system to a known state after a disruption, compromise, or failure.",
    },
    "IA-2": {
        "id": "IA-2",
        "family": "Identification and Authentication",
        "name": "Identification and Authentication (Organizational Users)",
        "description": "Uniquely identify and authenticate organizational users and require multi-factor authentication.",
    },
    "IA-5": {
        "id": "IA-5",
        "family": "Identification and Authentication",
        "name": "Authenticator Management",
        "description": "Manage system authenticators by verifying identity, establishing initial content, and ensuring administrative procedures are in place.",
    },
    "SC-7": {
        "id": "SC-7",
        "family": "System and Communications Protection",
        "name": "Boundary Protection",
        "description": "Monitor and control communications at the external boundary and key internal boundaries of the system.",
    },
    "SC-13": {
        "id": "SC-13",
        "family": "System and Communications Protection",
        "name": "Cryptographic Protection",
        "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of information.",
    },
    "SC-28": {
        "id": "SC-28",
        "family": "System and Communications Protection",
        "name": "Protection of Information at Rest",
        "description": "Protect the confidentiality and integrity of information at rest.",
    },
}

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 8,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


def _run_all_scanners():
    findings = []
    for scanner_fn in SCANNERS.values():
        findings.extend(scanner_fn())
    return findings


def _findings_to_dicts(findings):
    return [asdict(f) for f in findings]


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/scan")
def scan_all():
    findings = _run_all_scanners()
    return {"findings": _findings_to_dicts(findings), "count": len(findings)}


@app.get("/api/scan/{service}")
def scan_service(service: str):
    service = service.lower()
    if service not in SCANNERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown service '{service}'. Available: {', '.join(SCANNERS.keys())}",
        )
    findings = SCANNERS[service]()
    return {"service": service, "findings": _findings_to_dicts(findings), "count": len(findings)}


@app.get("/api/summary")
def get_summary():
    findings = _run_all_scanners()

    by_severity = defaultdict(int)
    by_service = defaultdict(int)
    nist_results = defaultdict(lambda: {"pass": 0, "fail": 0})

    failed_findings = [f for f in findings if f.status == Status.FAIL]

    for f in findings:
        if f.status == Status.FAIL:
            by_severity[f.severity.value] += 1
            by_service[f.service] += 1
        nist_results[f.nist_control]["pass" if f.status == Status.PASS else "fail"] += 1

    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in failed_findings)
    risk_score = max(0, 100 - penalty)

    nist_compliance = []
    for control_id, counts in sorted(nist_results.items()):
        total = counts["pass"] + counts["fail"]
        pct = round((counts["pass"] / total) * 100) if total > 0 else 0
        control_info = NIST_CONTROLS.get(control_id, {})
        nist_compliance.append({
            "control_id": control_id,
            "name": control_info.get("name", "Unknown"),
            "passed": counts["pass"],
            "failed": counts["fail"],
            "compliance_pct": pct,
        })

    total_controls = len(nist_compliance)
    fully_compliant = sum(1 for c in nist_compliance if c["failed"] == 0)
    overall_compliance_pct = round((fully_compliant / total_controls) * 100) if total_controls > 0 else 0

    return {
        "total_findings": len(failed_findings),
        "findings_by_severity": dict(by_severity),
        "findings_by_service": dict(by_service),
        "overall_risk_score": risk_score,
        "nist_compliance": {
            "controls": nist_compliance,
            "overall_compliance_pct": overall_compliance_pct,
        },
    }


@app.get("/api/nist-mapping")
def get_nist_mapping():
    return {"controls": list(NIST_CONTROLS.values())}
