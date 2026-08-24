from datetime import datetime

HIGH_RISK_ROLES = {
    "roles/owner": 50,
    "roles/editor": 40,
    "roles/iam.securityAdmin": 50,
    "roles/resourcemanager.organizationAdmin": 50,
    "roles/iam.serviceAccountTokenCreator": 50,
    "roles/iam.serviceAccountUser": 40,
    "roles/iam.workloadIdentityUser": 40,
}

INTERNAL_DOMAINS = ["your-company.com", "gmail.com"]
KNOWN_AUTOMATION = [
    "terraform-prod@your-company.iam.gserviceaccount.com",
    "github-actions@your-company.iam.gserviceaccount.com"
]
APPROVED_CORPORATE_IPS = [
    "192.168.1.1",
    "10.0.0.1",
    "41.102.197.190"
]

MITRE_MAPPINGS = {
    "T1098": {"id": "T1098", "name": "Account Manipulation"},
    "T1078.004": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
    "T1078": {"id": "T1078", "name": "Valid Accounts"},
    "T1098.004": {"id": "T1098.004", "name": "Account Manipulation: SSH Authorized Keys"}, # Closest to SA Keys
    "T1530": {"id": "T1530", "name": "Data from Cloud Storage"}
}

def calculate_identity_risk(member: str) -> int:
    if member.startswith("user:") or member.startswith("serviceAccount:"):
        email = member.split(":", 1)[1]
        domain = email.split("@")[-1] if "@" in email else ""
        if domain not in INTERNAL_DOMAINS and domain != "":
            return 30
    return 0

def calculate_privilege_risk(role: str) -> int:
    return HIGH_RISK_ROLES.get(role, 5)

def calculate_resource_criticality(resource_name: str) -> float:
    if not resource_name:
        return 1.0
    if "prod" in resource_name.lower():
        return 1.5
    elif "organization" in resource_name.lower():
        return 2.0
    return 1.0

def calculate_time_anomaly(timestamp_str: str) -> float:
    if not timestamp_str:
        return 1.0
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        if dt.weekday() >= 5:
            return 1.5
        if dt.hour < 6 or dt.hour > 19:
            return 1.2
    except Exception:
        pass
    return 1.0

def calculate_ip_risk(ip: str) -> int:
    if not ip or ip.startswith("private"): return 0 # Google internal IP
    return 0 if ip in APPROVED_CORPORATE_IPS else 20

def is_approved_automation(actor: str) -> bool:
    return actor in KNOWN_AUTOMATION or actor.endswith("system.gserviceaccount.com")

def calculate_automation_multiplier(actor: str) -> float:
    if actor in KNOWN_AUTOMATION or actor.endswith("system.gserviceaccount.com"):
        return 0.1
    return 1.0

def get_severity(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "INFO"
