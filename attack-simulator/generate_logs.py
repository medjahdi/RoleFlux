import json
import base64
import requests
import time
from datetime import datetime

# Local Functions Framework URL
FUNCTION_URL = "http://localhost:8080"

def create_pubsub(payload):
    return {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode()}}

def run_scenario(name, payload):
    print(f"\n--- Running: {name} ---")
    try:
        response = requests.post(FUNCTION_URL, json=create_pubsub(payload))
        if response.status_code != 200:
            print(f"Failed! Code: {response.status_code}")
    except Exception:
        print("ERROR: Make sure the functions-framework is running!")

# ---------------------------------------------------------
# 1. CRITICAL (Score 90+)
# Scenario: Data Leak (Public Bucket)
# Math: Base(90) * Prod(1.5) = 135 -> Capped at 100
# ---------------------------------------------------------
CRITICAL = {
    "timestamp": "2023-10-25T14:00:00Z", # Weekday
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": "engineer@your-company.com"},
        "requestMetadata": {"callerIp": "192.168.1.1"},
        "serviceName": "storage.googleapis.com",
        "methodName": "storage.setIamPermissions",
        "resourceName": "projects/_/buckets/customer-pii-prod",
        "request": {"policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}
    }
}

# ---------------------------------------------------------
# 2. HIGH (Score 70-89)
# Scenario: Privilege Escalation (Owner role to external user)
# Math: Role(50) + External(30) = 80. (Weekday, Non-Prod)
# Total: 80 * 1.0 * 1.0 = 80
# ---------------------------------------------------------
HIGH = {
    "timestamp": "2023-10-25T14:00:00Z", # Weekday
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": "admin@your-company.com"},
        "requestMetadata": {"callerIp": "192.168.1.1"},
        "methodName": "SetIamPolicy",
        "resourceName": "projects/my-dev-project",
        "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/owner", "member": "user:hacker@evil.com"}]}}
    }
}

# ---------------------------------------------------------
# 3. MEDIUM (Score 40-69)
# Scenario: Suspicious IP grants Viewer role
# Math: Role(5) + Bad IP(20) = 25. Weekend(1.5). Non-Prod.
# Total: 25 * 1.5 = 37.5 -> wait, let's use Prod(1.5) on weekday: 25 * 1.5 = 37. Not quite 40.
# Let's use Role(40 - Editor) to Internal User(0) on Weekday(1). 
# Total: 40 * 1.0 = 40
# ---------------------------------------------------------
MEDIUM = {
    "timestamp": "2023-10-25T14:00:00Z", # Weekday
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": "admin@your-company.com"},
        "requestMetadata": {"callerIp": "192.168.1.1"},
        "methodName": "SetIamPolicy",
        "resourceName": "projects/my-dev-project",
        "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/editor", "member": "user:dev@your-company.com"}]}}
    }
}

# ---------------------------------------------------------
# 4. LOW (Score 1-39)
# Scenario: Normal admin grants Viewer role
# Math: Role(5). Weekday(1.0). Non-Prod(1.0).
# Total: 5 * 1.0 = 5
# ---------------------------------------------------------
LOW = {
    "timestamp": "2023-10-25T14:00:00Z", # Weekday
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": "admin@your-company.com"},
        "requestMetadata": {"callerIp": "192.168.1.1"},
        "methodName": "SetIamPolicy",
        "resourceName": "projects/my-dev-project",
        "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/viewer", "member": "user:dev@your-company.com"}]}}
    }
}

# ---------------------------------------------------------
# 5. INFO (Score 0)
# Scenario: Approved Automation grants Viewer
# Math: Role(5). Weekday(1.0). Automation Mult(0.1).
# Total: int(5 * 0.1) = 0
# ---------------------------------------------------------
INFO = {
    "timestamp": "2023-10-25T14:00:00Z", # Weekday
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": "terraform-prod@your-company.iam.gserviceaccount.com"},
        "requestMetadata": {"callerIp": "192.168.1.1"},
        "methodName": "SetIamPolicy",
        "resourceName": "projects/my-dev-project",
        "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/viewer", "member": "user:dev@your-company.com"}]}}
    }
}


if __name__ == "__main__":
    print("Testing all 5 Severity Levels...")
    run_scenario("🚨 CRITICAL (Score 100)", CRITICAL)
    time.sleep(1)
    run_scenario("🔥 HIGH (Score 80)", HIGH)
    time.sleep(1)
    run_scenario("⚠️ MEDIUM (Score 40)", MEDIUM)
    time.sleep(1)
    run_scenario("👀 LOW (Score 5)", LOW)
    time.sleep(1)
    run_scenario("ℹ️ INFO (Score 0)", INFO)

