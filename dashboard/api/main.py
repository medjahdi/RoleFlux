from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google.cloud import bigquery
from pydantic import BaseModel
from typing import List, Optional
import os

app = FastAPI(title="RoleFlux Command Center API")

# Allow local frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ID = os.environ.get("TF_VAR_project_id", "roleflux-prod-1234")
DATASET_ID = "roleflux_analytics"
TABLE_ID = "findings"

try:
    client = bigquery.Client(project=PROJECT_ID)
except Exception as e:
    print(f"Warning: BigQuery client initialization failed. Ensure you have run 'gcloud auth application-default login'. Error: {e}")
    client = None

class FindingResponse(BaseModel):
    id: str
    timestamp: str
    risk_score: int
    severity: str
    description: str
    ai_summary: Optional[str] = None
    ai_remediation: Optional[str] = None
    targets: List[str] = []

class DashboardStats(BaseModel):
    total_events: int
    critical_events: int
    avg_score: int
    recent_findings: List[FindingResponse]

@app.get("/api/health")
def health_check():
    return {"status": "ok", "project": PROJECT_ID}

@app.get("/api/dashboard", response_model=DashboardStats)
def get_dashboard_data():
    if not client:
        raise HTTPException(status_code=500, detail="BigQuery client not initialized.")
        
    query = f"""
    SELECT 
        GENERATE_UUID() as id, timestamp, risk_score, severity, description
    FROM 
        `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
    ORDER BY 
        timestamp DESC
    LIMIT 50
    """
    
    try:
        query_job = client.query(query)
        results = query_job.result()
        
        findings = []
        total_score = 0
        critical_count = 0
        
        for row in results:
            finding = FindingResponse(
                id=str(row["id"]),
                timestamp=row["timestamp"].isoformat(),
                risk_score=row["risk_score"],
                severity=row["severity"],
                description=row["description"]
            )
            findings.append(finding)
            total_score += finding.risk_score
            if finding.severity == "CRITICAL":
                critical_count += 1
                
        total_events = len(findings)
        avg_score = int(total_score / total_events) if total_events > 0 else 0
        
        return DashboardStats(
            total_events=total_events,
            critical_events=critical_count,
            avg_score=avg_score,
            recent_findings=findings
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
