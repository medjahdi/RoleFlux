import os
import json
from google.cloud import bigquery

# Initialize BigQuery client (It automatically picks up GCP credentials from the Cloud Function environment)
try:
    bq_client = bigquery.Client()
except Exception as e:
    print(f"[BigQuery] Failed to initialize client: {e}")
    bq_client = None

def write_to_bigquery(finding_json: str):
    if not bq_client:
        return
        
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT") or bq_client.project
    dataset_id = os.environ.get("BIGQUERY_DATASET", "roleflux_analytics")
    table_id = os.environ.get("BIGQUERY_TABLE", "findings")
    
    table_ref = f"{project_id}.{dataset_id}.{table_id}"
    
    try:
        finding = json.loads(finding_json)
        
        # BigQuery expects a list of dictionaries for streaming inserts
        # We extract mitre technique IDs into an array of strings for easier querying
        mitre_ids = [t.get("id") for t in finding.get("mitre_techniques", [])]
        
        row_to_insert = {
            "timestamp": finding.get("timestamp"), # We should probably add timestamp to Finding model, but let's grab it or generate it
            "risk_score": finding.get("risk_score"),
            "severity": finding.get("severity"),
            "description": finding.get("description"),
            "actors": finding.get("actors", []),
            "targets": finding.get("targets", []),
            "mitre_techniques": mitre_ids,
            "raw_event": json.dumps(finding.get("raw_event", {}))
        }
        
        # The Finding model currently doesn't output 'timestamp' explicitly at the top level in model_dump_json?
        # Let's ensure timestamp is grabbed from raw_event if not at top level
        if not row_to_insert["timestamp"] and "timestamp" in finding.get("raw_event", {}):
            row_to_insert["timestamp"] = finding["raw_event"]["timestamp"]
            
        errors = bq_client.insert_rows_json(table_ref, [row_to_insert])
        if errors:
            print(f"[BigQuery] Errors occurred while inserting rows: {errors}")
        else:
            print("[BigQuery] Successfully streamed finding to Data Lake.")
    except Exception as e:
        print(f"[BigQuery] Failed to write finding: {e}")
