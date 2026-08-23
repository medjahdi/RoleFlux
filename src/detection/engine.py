from typing import Optional, List
from src.models.audit_log import GCPAuditLog
from src.models.finding import Finding, MitreTechnique
from src.detection.rules import (
    calculate_identity_risk,
    calculate_privilege_risk,
    calculate_resource_criticality,
    get_severity,
    MITRE_MAPPINGS
)
from src.state.firestore import db

def analyze_iam_change(audit_log: GCPAuditLog) -> Optional[Finding]:
    """Analyzes a GCP Audit Log for risky IAM changes."""
    payload = audit_log.protoPayload
    
    if payload.methodName != "SetIamPolicy":
        return None
    
    if not payload.serviceData or not payload.serviceData.policyDelta:
        return None
        
    deltas = payload.serviceData.policyDelta.bindingDeltas
    if not deltas:
        return None
        
    max_risk_score = 0
    actors = set()
    actor_email = ""
    if payload.authenticationInfo and payload.authenticationInfo.principalEmail:
        actor_email = payload.authenticationInfo.principalEmail
        actors.add(actor_email)
        
    targets = set()
    techniques = set()
    descriptions = []

    # State Enrichment
    enriched_by_state = False
    if actor_email:
        if db.check_suspicious_history(actor_email):
            enriched_by_state = True
        db.log_event(actor_email, "SetIamPolicy")

    for delta in deltas:
        if delta.action == "ADD":
            id_risk = calculate_identity_risk(delta.member)
            priv_risk = calculate_privilege_risk(delta.role)
            crit_multiplier = calculate_resource_criticality(payload.resourceName)
            
            base_score = id_risk + priv_risk
            
            # State context penalty
            if enriched_by_state:
                base_score += 20 
                
            total_score = min(int(base_score * crit_multiplier), 100)
            
            if total_score > max_risk_score:
                max_risk_score = total_score
                
            targets.add(delta.member)
            
            if priv_risk >= 40:
                techniques.add("T1098")
            if id_risk > 0:
                techniques.add("T1078.004")
                
            descriptions.append(f"Granted {delta.role} to {delta.member}")
            
    if max_risk_score == 0:
        return None
        
    mitre_list = [MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques]
    
    return Finding(
        risk_score=max_risk_score,
        severity=get_severity(max_risk_score),
        description="; ".join(descriptions),
        mitre_techniques=mitre_list,
        actors=list(actors),
        targets=list(targets),
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched_by_state
    )
