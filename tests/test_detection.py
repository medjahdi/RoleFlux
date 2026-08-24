import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.models.audit_log import GCPAuditLog
from src.detection.engine import analyze_log
from src.state.firestore import db

MOCK_BASE_LOG = {
  "timestamp": "2023-10-27T14:00:00Z", # Friday 2 PM (Normal)
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "admin@your-company.com"
    },
    "requestMetadata": {
        "callerIp": "192.168.1.1" # VPN IP
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

def create_log(role: str, member: str, project: str, actor: str = "admin@your-company.com", ip: str = "192.168.1.1", ts: str = "2023-10-27T14:00:00Z") -> GCPAuditLog:
    import copy
    log = copy.deepcopy(MOCK_BASE_LOG)
    log["timestamp"] = ts
    log["protoPayload"]["resourceName"] = project
    log["protoPayload"]["authenticationInfo"]["principalEmail"] = actor
    log["protoPayload"]["requestMetadata"]["callerIp"] = ip
    log["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {
            "action": "ADD",
            "role": role,
            "member": member
        }
    ]
    return GCPAuditLog(**log)

def test_false_positive_suppression():
    # Terraform making a change should be severely penalized in score
    log = create_log(
        role="roles/editor", 
        member="user:dev@your-company.com", 
        project="projects/prod",
        actor="terraform-prod@your-company.iam.gserviceaccount.com"
    )
    finding = analyze_log(log)
    
    assert finding is not None
    # Usually: Editor(40) * Prod(1.5) = 60. 
    # With automation multiplier (0.1): 60 * 0.1 = 6
    assert finding.risk_score <= 10
    assert finding.severity == "LOW" or finding.severity == "INFO"

def test_off_hours_foreign_ip_escalation():
    # Sunday 3 AM, foreign IP
    log = create_log(
        role="roles/iam.serviceAccountTokenCreator", 
        member="user:attacker@gmail.com", 
        project="projects/prod",
        actor="compromised-admin@your-company.com",
        ip="203.0.113.1", # Outside VPN
        ts="2023-10-29T03:00:00Z" # Sunday 3 AM
    )
    finding = analyze_log(log)
    
    assert finding is not None
    # Role(50) + External Target(30) + Bad IP(20) = 100
    # Multipliers: Prod(1.5) * Weekend(1.5) = 2.25
    # Total = 225 -> capped at 100
    assert finding.risk_score == 100
    assert finding.severity == "CRITICAL"
    mitre_ids = [t.id for t in finding.mitre_techniques]
    assert "T1078" in mitre_ids # Valid Accounts (due to IP anomaly)

def test_firewall_exposure():
    # Opening SSH to the world
    log_dict = MOCK_BASE_LOG.copy()
    log_dict["timestamp"] = "2023-10-27T14:00:00Z"
    log_dict["protoPayload"]["methodName"] = "v1.compute.firewalls.insert"
    log_dict["protoPayload"]["resourceName"] = "projects/prod/firewalls/allow-ssh"
    log_dict["protoPayload"]["request"] = {
        "sourceRanges": ["0.0.0.0/0", "10.0.0.0/8"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22", "80"]}]
    }
    
    log = GCPAuditLog(**log_dict)
    finding = analyze_log(log)
    
    assert finding is not None
    assert finding.risk_score >= 80 # Highly critical
    assert finding.severity == "CRITICAL"
    mitre_ids = [t.id for t in finding.mitre_techniques]
    assert "T1562.007" in mitre_ids

def test_crypto_mining_compute():
    # Creating a massive GPU instance with default SA
    log_dict = MOCK_BASE_LOG.copy()
    log_dict["timestamp"] = "2023-10-27T14:00:00Z"
    log_dict["protoPayload"]["methodName"] = "v1.compute.instances.insert"
    log_dict["protoPayload"]["resourceName"] = "projects/prod/instances/miner-01"
    log_dict["protoPayload"]["request"] = {
        "machineType": "projects/prod/zones/us-central1-a/machineTypes/a2-highgpu-8g",
        "serviceAccounts": [
            {"email": "123456789-compute@developer.gserviceaccount.com"}
        ]
    }
    
    log = GCPAuditLog(**log_dict)
    finding = analyze_log(log)
    
    assert finding is not None
    assert finding.risk_score >= 90 # High power + default SA
    assert finding.severity == "CRITICAL"
    mitre_ids = [t.id for t in finding.mitre_techniques]
    assert "T1496" in mitre_ids
    assert "T1078.004" in mitre_ids
