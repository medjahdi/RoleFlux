import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.models.audit_log import GCPAuditLog
from src.detection.engine import analyze_iam_change
from src.outputs.slack import send_slack_alert
from src.outputs.bigquery import write_to_bigquery

MOCK_LOG = {
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "admin@your-company.com"
    },
    "requestMetadata": {
      "callerIp": "192.168.1.1"
    },
    "methodName": "SetIamPolicy",
    "resourceName": "projects/my-prod-project",
    "serviceData": {
      "policyDelta": {
        "bindingDeltas": []
      }
    }
  }
}

def simulate_attack(role: str, member: str, project: str = "projects/my-prod-project", actor: str = "admin@your-company.com"):
    import copy
    log = copy.deepcopy(MOCK_LOG)
    log["protoPayload"]["resourceName"] = project
    log["protoPayload"]["authenticationInfo"]["principalEmail"] = actor
    log["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {
            "action": "ADD",
            "role": role,
            "member": member
        }
    ]
    
    audit_log = GCPAuditLog(**log)
    print(f"--- Simulating: {actor} granted {role} to {member} in {project} ---")
    finding = analyze_iam_change(audit_log)
    
    if finding:
        print(f"🚨 ALERT [{finding.severity} - Score: {finding.risk_score}]: {finding.description}")
        print(f"   Context Enriched (Firestore): {finding.context_enriched}")
        print(f"   MITRE Techniques: {[t.name for t in finding.mitre_techniques]}")
        # Mock sending to outputs
        finding_json = finding.model_dump_json(indent=2)
        send_slack_alert("Slack Alert Generated (Hidden for brevity)")
        write_to_bigquery("BigQuery Row Inserted (Hidden for brevity)\n")
    else:
        print("✅ No actionable risk detected.\n")

if __name__ == "__main__":
    print("🚀 Starting RoleFlux Attack Simulator (Enterprise Architecture)...\n")
    
    # Scenario 1: High Risk
    simulate_attack("roles/owner", "user:attacker@gmail.com")
    
    # Scenario 2: Same actor does it again (Context Enrichment from Firestore should increase score)
    simulate_attack("roles/editor", "user:another@gmail.com")
