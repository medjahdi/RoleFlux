import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.models.audit_log import GCPAuditLog
from src.detection.engine import analyze_iam_change
from src.state.firestore import db

MOCK_BASE_LOG = {
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "admin@your-company.com"
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

def create_log(role: str, member: str, project: str) -> GCPAuditLog:
    import copy
    log = copy.deepcopy(MOCK_BASE_LOG)
    log["protoPayload"]["resourceName"] = project
    log["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {
            "action": "ADD",
            "role": role,
            "member": member
        }
    ]
    return GCPAuditLog(**log)

def test_high_risk_external_owner():
    log = create_log("roles/owner", "user:attacker@gmail.com", "projects/prod-db")
    finding = analyze_iam_change(log)
    
    assert finding is not None
    assert finding.severity == "CRITICAL"
    mitre_ids = [t.id for t in finding.mitre_techniques]
    assert "T1098" in mitre_ids
    assert "T1078.004" in mitre_ids

def test_state_enrichment():
    # First action
    log1 = create_log("roles/editor", "user:dev1@your-company.com", "projects/sandbox")
    log1.protoPayload.authenticationInfo.principalEmail = "shady-admin@your-company.com"
    finding1 = analyze_iam_change(log1)
    
    # Second action by same user
    log2 = create_log("roles/editor", "user:dev2@your-company.com", "projects/sandbox")
    log2.protoPayload.authenticationInfo.principalEmail = "shady-admin@your-company.com"
    finding2 = analyze_iam_change(log2)
    
    assert finding2.context_enriched is True
    assert finding2.risk_score > finding1.risk_score
