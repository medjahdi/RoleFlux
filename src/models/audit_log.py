from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

class AuthenticationInfo(BaseModel):
    principalEmail: Optional[str] = None

class RequestMetadata(BaseModel):
    callerIp: Optional[str] = None
    callerSuppliedUserAgent: Optional[str] = None

class BindingDelta(BaseModel):
    action: str
    role: str
    member: str

class PolicyDelta(BaseModel):
    bindingDeltas: List[BindingDelta] = Field(default_factory=list)

class ServiceData(BaseModel):
    policyDelta: Optional[PolicyDelta] = None

class AuditLogProtoPayload(BaseModel):
    type_name: Optional[str] = Field(alias="@type", default=None)
    authenticationInfo: Optional[AuthenticationInfo] = None
    requestMetadata: Optional[RequestMetadata] = None
    serviceName: Optional[str] = None
    methodName: Optional[str] = None
    resourceName: Optional[str] = None
    
    # IAM Changes
    serviceData: Optional[ServiceData] = None
    
    # Storage & Generic API payloads
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None

class GCPAuditLog(BaseModel):
    protoPayload: AuditLogProtoPayload
    timestamp: Optional[str] = None
