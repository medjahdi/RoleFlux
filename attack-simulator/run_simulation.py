import json
import subprocess
import time
from datetime import datetime, timezone

PROJECT = "roleflux-prod-1234"
TOPIC = "roleflux-logs"

def get_base_log():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": {"principalEmail": "admin@your-company.com"},
            "requestMetadata": {"callerIp": "203.0.113.1"}, # External IP
            "resourceName": f"projects/{PROJECT}"
        }
    }

def inject_payload(name: str, log_data: dict):
    print(f"\n[Red Team] Injecting payload: {name}")
    try:
        json_str = json.dumps(log_data)
        cmd = [
            "gcloud", "pubsub", "topics", "publish", TOPIC,
            "--message", json_str,
            "--project", PROJECT
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"Success! Message ID: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to publish: {e.stderr}")

def simulate_firewall_exposure():
    log = get_base_log()
    log["protoPayload"]["methodName"] = "v1.compute.firewalls.insert"
    log["protoPayload"]["resourceName"] = f"projects/{PROJECT}/firewalls/allow-ssh-internet"
    log["protoPayload"]["request"] = {
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]
    }
    inject_payload("Firewall SSH Exposure", log)

def simulate_crypto_mining():
    log = get_base_log()
    log["protoPayload"]["methodName"] = "v1.compute.instances.insert"
    log["protoPayload"]["resourceName"] = f"projects/{PROJECT}/instances/miner-gpu-instance"
    log["protoPayload"]["request"] = {
        "machineType": f"projects/{PROJECT}/zones/us-central1-a/machineTypes/a2-highgpu-8g",
        "serviceAccounts": [
            {"email": "123456789-compute@developer.gserviceaccount.com"}
        ]
    }
    inject_payload("Crypto-Mining Instance", log)

def simulate_privilege_escalation():
    log = get_base_log()
    log["protoPayload"]["methodName"] = "SetIamPolicy"
    log["protoPayload"]["serviceData"] = {
        "policyDelta": {
            "bindingDeltas": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:attacker@evil.com"
                }
            ]
        }
    }
    inject_payload("IAM Privilege Escalation", log)

def simulate_benign_action():
    log = get_base_log()
    log["protoPayload"]["authenticationInfo"]["principalEmail"] = "github-actions-deployer@roleflux-prod-1234.iam.gserviceaccount.com"
    log["protoPayload"]["methodName"] = "SetIamPolicy"
    log["protoPayload"]["serviceData"] = {
        "policyDelta": {
            "bindingDeltas": [
                {
                    "action": "ADD",
                    "role": "roles/viewer",
                    "member": "serviceAccount:github-actions-deployer@roleflux-prod-1234.iam.gserviceaccount.com"
                }
            ]
        }
    }
    inject_payload("Benign GitHub Action Deploy", log)

if __name__ == "__main__":
    simulate_benign_action()
    time.sleep(2)
    simulate_firewall_exposure()
    time.sleep(2)
    simulate_crypto_mining()
    time.sleep(2)
    simulate_privilege_escalation()
    print("\n[Red Team] All attacks simulated.")
