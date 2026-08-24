from typing import List, Dict, Any
from pydantic import BaseModel, Field
import uuid
import datetime

class MitreTechnique(BaseModel):
    id: str
    name: str

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    risk_score: int = Field(ge=0, le=100)
    severity: str
    description: str
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    actors: List[str] = Field(default_factory=list)
    targets: List[str] = Field(default_factory=list)
    raw_event: Dict[str, Any]
    context_enriched: bool = False # Was this enriched by Firestore state?
    ai_summary: str | None = None
    ai_remediation: str | None = None
