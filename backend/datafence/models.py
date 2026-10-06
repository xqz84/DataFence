"""Allowlisted detector contracts. Ground truth belongs only to evaluation."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


EventType = Literal["LOGIN", "QUERY", "EXPORT", "COMPRESS", "API", "UPLOAD", "AI_PROMPT"]
Channel = Literal["internal", "approved_partner", "external", "internal_ai"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ScenarioId = Literal["insider", "stolen_account", "bulk_export", "api_scraping", "ai_leak", "combined", "normal", "approved_batch"]


class Employee(Contract):
    id: str
    name: str
    role: str = "客户经理"
    department: str = "零售金融部"
    region: str
    known_device: str
    baseline_daily_records: int = 30
    baseline_daily_queries: int = 12
    synthetic: Literal[True] = True


class BusinessTask(Contract):
    id: str
    employee_id: str
    purpose: str
    regions: list[str]
    max_records: int
    valid_from: datetime
    valid_until: datetime
    allowed_hours: list[int]
    approved_channels: list[Channel] = Field(default_factory=lambda: ["internal", "internal_ai"])
    allow_export: bool = False
    quota_scope: Literal["session", "task_lifetime"] = "session"
    synthetic: Literal[True] = True


class SecurityEvent(Contract):
    event_id: str = Field(min_length=8, max_length=80)
    session_id: str = Field(min_length=8, max_length=80)
    employee_id: str = Field(min_length=1, max_length=40)
    timestamp: datetime
    event_type: EventType
    task_id: str | None = None
    purpose: str = Field(default="客户服务", max_length=200)
    resource: str = Field(default="customers", max_length=80)
    record_count: int = Field(default=0, ge=0, le=50000)
    regions: list[str] = Field(default_factory=list, max_length=32)
    device_id: str = Field(default="", max_length=80)
    sensitivity: int = Field(default=80, ge=0, le=100)
    channel: Channel = "internal"
    object_id: str | None = Field(default=None, max_length=80)
    parent_object_id: str | None = Field(default=None, max_length=80)
    prompt: str | None = Field(default=None, max_length=2000)
    synthetic: Literal[True] = True

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone aware")
        return value


class IntentResult(Contract):
    role_match: float
    purpose_match: float
    scope_match: float
    time_match: float
    trust: float
    status: Literal["supported", "mismatch", "insufficient_evidence"]
    evidence: list[str]


class Analysis(Contract):
    event_id: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    dimensions: dict[str, float]
    intent: IntentResult
    rules: list[str]
    anomaly_score: float
    explanation: str
    actions: list[str]
    blocked: bool
    chain: list[dict]
    analysis_source: str = "rules+isolation_forest+purpose"
    processing_ms: float = 0
    model_version: str = "iforest-v1"


class SimulationRequest(Contract):
    scenario_id: ScenarioId = "combined"
    employee_id: str = "E0038"
    record_count: int = Field(default=18000, ge=1, le=50000)
    interval_ms: int = Field(default=500, ge=0, le=2000)
    seed: int = Field(default=42, ge=0, le=2147483647)
    export: bool = True
    compress: bool = True
    upload: bool = True


class EvaluationRequest(Contract):
    seed: int = Field(default=20260919, ge=0, le=2147483647)
    sessions: int = Field(default=160, ge=24, le=1000)
