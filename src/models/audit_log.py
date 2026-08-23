from typing import List, Optional, Any
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
    serviceData: Optional[ServiceData] = None

class GCPAuditLog(BaseModel):
    protoPayload: AuditLogProtoPayload
