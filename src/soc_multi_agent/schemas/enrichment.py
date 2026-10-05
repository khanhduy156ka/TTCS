from enum import Enum

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    USER = "user"
    HOST = "host"


class SecurityEntity(BaseModel):
    entity_type: EntityType
    value: str
    source_field: str


class MitreTechniqueContext(BaseModel):
    technique_id: str
    name: str

    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)

    revoked: bool = False
    deprecated: bool = False

    source_url: str | None = None


class ThreatIntelFinding(BaseModel):
    provider: str
    entity_type: EntityType
    value: str

    # known=True nghia la provider co object/report cho IOC, False chi la provider chua biet IOC luc lookup chu khong phai benign
    known: bool = True

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

    reputation: int | None = None

    categories: list[str] = Field(
        default_factory=list
    )

    file_type: str | None = None

    country: str | None = None
    as_owner: str | None = None


class EnrichmentResult(BaseModel):
    alert_id: str

    entities: list[SecurityEntity] = Field(
        default_factory=list
    )

    mitre_techniques: list[MitreTechniqueContext] = Field(
        default_factory=list
    )

    threat_intel: list[ThreatIntelFinding] = Field(
        default_factory=list
    )


class EnrichmentAssessment(BaseModel):
    alert_id: str

    risk_level: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    relevant_findings: list[str] = Field(
        default_factory=list
    )

    inconsistencies: list[str] = Field(
        default_factory=list
    )

    requires_investigation: bool

    summary: str
    recommended_next_step: str
