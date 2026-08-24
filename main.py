import base64
import json
import functions_framework
from cloudevents.http import CloudEvent
from src.models.audit_log import GCPAuditLog
from src.detection.engine import analyze_log
from src.outputs.slack import send_slack_alert
from src.outputs.bigquery import write_to_bigquery

@functions_framework.cloud_event
def roleflux_entrypoint(cloud_event: CloudEvent):
    """
    Background Cloud Function triggered by Pub/Sub.
    """
    # Extract the Pub/Sub message data
    pubsub_message = cloud_event.data.get("message")
    if not pubsub_message:
        print("Error: No Pub/Sub message found in event.")
        return

    data_b64 = pubsub_message.get("data")
    if not data_b64:
        print("Error: Empty data field in Pub/Sub message.")
        return

    # Decode the base64 JSON string
    try:
        raw_log_str = base64.b64decode(data_b64).decode("utf-8")
        raw_log_json = json.loads(raw_log_str)
    except Exception as e:
        print(f"Failed to decode or parse JSON: {e}")
        return # Consider routing to a Dead Letter Queue from here in a real scenario

    # Parse with Pydantic
    try:
        audit_log = GCPAuditLog(**raw_log_json)
    except Exception as e:
        print(f"Pydantic Validation Error (Log discarded): {e}")
        return

    # Run the Detection Engine
    finding = analyze_log(audit_log)
    
    if finding:
        finding_json = finding.model_dump_json(indent=2)
        print(f"Finding Generated: Score {finding.risk_score}")
        
        # Always write to BigQuery for analytics
        write_to_bigquery(finding_json)
        
        # Route ALL alerts to Slack for triage
        send_slack_alert(finding_json)
    else:
        print("Log processed: No actionable risk found.")
