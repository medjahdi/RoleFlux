from typing import Optional, List
from src.models.audit_log import GCPAuditLog
from src.models.finding import Finding, MitreTechnique
from src.detection.rules import (
    calculate_identity_risk,
    calculate_privilege_risk,
    calculate_resource_criticality,
    calculate_time_anomaly,
    calculate_ip_risk,
    is_approved_automation,
    get_severity,
    MITRE_MAPPINGS
)
from src.state.firestore import db

def analyze_iam_change(audit_log: GCPAuditLog, actor: str, ip: str, time_mult: float, auto_mult: float, enriched: bool) -> Optional[Finding]:
    payload = audit_log.protoPayload
    if not payload.serviceData or not payload.serviceData.policyDelta:
        return None
        
    deltas = payload.serviceData.policyDelta.bindingDeltas
    if not deltas:
        return None
        
    max_score = 0
    targets = set()
    techniques = set()
    descriptions = []

    for delta in deltas:
        if delta.action == "ADD":
            id_risk = calculate_identity_risk(delta.member)
            priv_risk = calculate_privilege_risk(delta.role)
            crit_mult = calculate_resource_criticality(payload.resourceName)
            ip_risk = calculate_ip_risk(ip)
            
            base = id_risk + priv_risk + ip_risk + (20 if enriched else 0)
            score = min(int(base * crit_mult * time_mult * auto_mult), 100)
            
            if score > max_score: max_score = score
            targets.add(delta.member)
            
            if priv_risk >= 40: techniques.add("T1098")
            if id_risk > 0: techniques.add("T1078.004")
            if ip_risk > 0: techniques.add("T1078")
            descriptions.append(f"Granted {delta.role} to {delta.member}")
            
    if max_score == 0: return None
    
    return Finding(
        risk_score=max_score,
        severity=get_severity(max_score),
        description="; ".join(descriptions),
        mitre_techniques=[MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques],
        actors=[actor],
        targets=list(targets),
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched
    )

def analyze_key_creation(audit_log: GCPAuditLog, actor: str, ip: str, time_mult: float, auto_mult: float, enriched: bool) -> Optional[Finding]:
    # Creating a Service Account Key is inherently high risk (Backdoor)
    payload = audit_log.protoPayload
    
    target_sa = payload.resourceName or "unknown-sa"
    crit_mult = calculate_resource_criticality(target_sa)
    ip_risk = calculate_ip_risk(ip)
    
    base_score = 70 + ip_risk + (20 if enriched else 0)
    score = min(int(base_score * crit_mult * time_mult * auto_mult), 100)
    
    if score == 0: return None
    
    techniques = ["T1098.004"]
    if ip_risk > 0: techniques.add("T1078")

    return Finding(
        risk_score=score,
        severity=get_severity(score),
        description=f"Service Account Key created for {target_sa}",
        mitre_techniques=[MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques],
        actors=[actor],
        targets=[target_sa],
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched
    )

def analyze_storage_leak(audit_log: GCPAuditLog, actor: str, ip: str, time_mult: float, auto_mult: float, enriched: bool) -> Optional[Finding]:
    # Modifying storage bucket IAM
    payload = audit_log.protoPayload
    if not payload.request or "policy" not in payload.request:
        return None
        
    bindings = payload.request["policy"].get("bindings", [])
    exposed = False
    
    for binding in bindings:
        members = binding.get("members", [])
        if "allUsers" in members or "allAuthenticatedUsers" in members:
            exposed = True
            break
            
    if not exposed:
        return None
        
    target_bucket = payload.resourceName or "unknown-bucket"
    crit_mult = calculate_resource_criticality(target_bucket)
    ip_risk = calculate_ip_risk(ip)
    
    # Public exposure is critical
    base_score = 90 + ip_risk + (20 if enriched else 0)
    score = min(int(base_score * crit_mult * time_mult * auto_mult), 100)
    
    techniques = ["T1530"]
    if ip_risk > 0: techniques.add("T1078")

    return Finding(
        risk_score=score,
        severity=get_severity(score),
        description=f"Data Leak: Bucket {target_bucket} made PUBLIC (allUsers)",
        mitre_techniques=[MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques],
        actors=[actor],
        targets=[target_bucket],
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched
    )

def analyze_firewall_change(audit_log: GCPAuditLog, actor: str, ip: str, time_mult: float, auto_mult: float, enriched: bool) -> Optional[Finding]:
    payload = audit_log.protoPayload
    if not payload.request or "sourceRanges" not in payload.request or "allowed" not in payload.request:
        return None
        
    source_ranges = payload.request.get("sourceRanges", [])
    if "0.0.0.0/0" not in source_ranges:
        return None
        
    allowed = payload.request.get("allowed", [])
    exposed_ports = []
    for rule in allowed:
        for port in rule.get("ports", []):
            if port in ["22", "3389", "3306", "5432"]:
                exposed_ports.append(port)
                
    if not exposed_ports:
        return None
        
    target_firewall = payload.resourceName or "unknown-firewall"
    crit_mult = calculate_resource_criticality(target_firewall)
    ip_risk = calculate_ip_risk(ip)
    
    base_score = 80 + ip_risk + (20 if enriched else 0)
    score = min(int(base_score * crit_mult * time_mult * auto_mult), 100)
    
    techniques = ["T1562.007"]
    if ip_risk > 0: techniques.append("T1078")

    return Finding(
        risk_score=score,
        severity=get_severity(score),
        description=f"High-Risk Ports {exposed_ports} exposed to 0.0.0.0/0 on {target_firewall}",
        mitre_techniques=[MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques],
        actors=[actor],
        targets=[target_firewall],
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched
    )

def analyze_compute_creation(audit_log: GCPAuditLog, actor: str, ip: str, time_mult: float, auto_mult: float, enriched: bool) -> Optional[Finding]:
    payload = audit_log.protoPayload
    if not payload.request or "machineType" not in payload.request:
        return None
        
    machine_type = payload.request.get("machineType", "").lower()
    service_accounts = payload.request.get("serviceAccounts", [])
    
    is_high_power = any(keyword in machine_type for keyword in ["gpu", "n2-standard-32", "c2-standard-60", "a2-highgpu"])
    uses_default_sa = any("compute@developer.gserviceaccount.com" in sa.get("email", "") for sa in service_accounts)
    
    if not (is_high_power or uses_default_sa):
        return None
        
    target_instance = payload.resourceName or "unknown-instance"
    crit_mult = calculate_resource_criticality(target_instance)
    ip_risk = calculate_ip_risk(ip)
    
    base_score = 70 + ip_risk + (20 if enriched else 0)
    if is_high_power and uses_default_sa:
        base_score += 20
        
    score = min(int(base_score * crit_mult * time_mult * auto_mult), 100)
    
    techniques = ["T1496"]
    if uses_default_sa: techniques.append("T1078.004")
    if ip_risk > 0: techniques.append("T1078")

    desc_parts = []
    if is_high_power: desc_parts.append(f"High-power machine type ({machine_type.split('/')[-1]})")
    if uses_default_sa: desc_parts.append("Default Compute SA")
    
    return Finding(
        risk_score=score,
        severity=get_severity(score),
        description=f"Suspicious Compute Instance created: {' and '.join(desc_parts)}",
        mitre_techniques=[MitreTechnique(**MITRE_MAPPINGS[t]) for t in techniques],
        actors=[actor],
        targets=[target_instance],
        raw_event=audit_log.model_dump(by_alias=True),
        context_enriched=enriched
    )

def analyze_log(audit_log: GCPAuditLog) -> Optional[Finding]:
    """Master Router for all GCP Events"""
    payload = audit_log.protoPayload
    
    actor = ""
    if payload.authenticationInfo and payload.authenticationInfo.principalEmail:
        actor = payload.authenticationInfo.principalEmail
        
    ip = ""
    if payload.requestMetadata and payload.requestMetadata.callerIp:
        ip = payload.requestMetadata.callerIp

    # State Enrichment
    enriched = False
    if actor:
        if db.check_suspicious_history(actor):
            enriched = True
        db.log_event(actor, payload.methodName or "Unknown")

    time_mult = calculate_time_anomaly(audit_log.timestamp)
    auto_mult = 0.1 if is_approved_automation(actor) else 1.0

    # Routing
    if payload.methodName == "SetIamPolicy":
        return analyze_iam_change(audit_log, actor, ip, time_mult, auto_mult, enriched)
    elif payload.methodName == "google.iam.admin.v1.CreateServiceAccountKey":
        return analyze_key_creation(audit_log, actor, ip, time_mult, auto_mult, enriched)
    elif payload.methodName == "storage.setIamPermissions":
        return analyze_storage_leak(audit_log, actor, ip, time_mult, auto_mult, enriched)
    elif payload.methodName in ["v1.compute.firewalls.insert", "v1.compute.firewalls.patch"]:
        return analyze_firewall_change(audit_log, actor, ip, time_mult, auto_mult, enriched)
    elif payload.methodName == "v1.compute.instances.insert":
        return analyze_compute_creation(audit_log, actor, ip, time_mult, auto_mult, enriched)
        
    return None
