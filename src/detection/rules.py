HIGH_RISK_ROLES = {
    "roles/owner": 50,
    "roles/editor": 40,
    "roles/iam.securityAdmin": 40,
    "roles/resourcemanager.organizationAdmin": 50,
}

# Domains considered internal/safe. Anything not here is external.
INTERNAL_DOMAINS = ["your-company.com"]

MITRE_MAPPINGS = {
    "T1098": {"id": "T1098", "name": "Account Manipulation"},
    "T1078.004": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"}
}

def calculate_identity_risk(member: str) -> int:
    """Calculates risk based on identity (e.g., external domains are higher risk)."""
    if member.startswith("user:") or member.startswith("serviceAccount:"):
        email = member.split(":", 1)[1]
        domain = email.split("@")[-1] if "@" in email else ""
        if domain not in INTERNAL_DOMAINS and domain != "":
            return 30
    return 0

def calculate_privilege_risk(role: str) -> int:
    """Calculates risk based on the IAM role being assigned."""
    return HIGH_RISK_ROLES.get(role, 5)

def calculate_resource_criticality(resource_name: str) -> float:
    """Calculates a multiplier based on the environment/resource."""
    if not resource_name:
        return 1.0
    if "prod" in resource_name.lower():
        return 1.5
    elif "organization" in resource_name.lower():
        return 2.0
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
