"""
SOCentinel — Pydantic models.
Simple models matching the DB schema for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class NormalizedEvent(BaseModel):
    """OCSF-normalized security event."""
    id: str
    alert_id: Optional[str] = None
    timestamp: str
    event_type: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[str] = None
    log_line: str
    ocsf_category: Optional[str] = None
    metadata: Optional[dict] = None


class Alert(BaseModel):
    """Security alert from detection rules."""
    id: str
    title: str
    severity: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    status: str = "open"
    rule_name: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[str] = None
    timestamp: str
    raw_log: Optional[str] = None
    ocsf_category: Optional[str] = None
    created_at: Optional[str] = None


class Asset(BaseModel):
    """Network asset / host."""
    id: str
    hostname: str
    asset_type: str
    criticality: str
    owner: Optional[str] = None
    ip_address: Optional[str] = None
    autonomy_tier: int = 1
    metadata: Optional[dict] = None


class User(BaseModel):
    """User identity from directory."""
    id: str
    username: str
    full_name: str
    department: Optional[str] = None
    role: Optional[str] = None
    is_privileged: bool = False
    typical_hours: Optional[str] = None
    typical_ips: Optional[List[str]] = None
    risk_score: float = 0.0
    metadata: Optional[dict] = None


class Case(BaseModel):
    """Investigation case."""
    id: str
    title: str
    status: str = "open"
    severity: Optional[str] = None
    analyst_notes: Optional[str] = None
    created_at: Optional[str] = None
    closed_at: Optional[str] = None
    resolution: Optional[str] = None
    resolution_time_minutes: Optional[int] = None
    is_true_positive: Optional[bool] = None
    attack_type: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    metadata: Optional[dict] = None


class ActionSuggestion(BaseModel):
    """SOAR action suggested by the AI."""
    id: str
    label: str
    tier: int = Field(..., ge=0, le=2)
    reason: str
    risk: str
    status: str = "pending"  # pending, approved, executed, rejected
    requires_mfa: bool = False


class TriageResult(BaseModel):
    """Result of AI triage on an alert."""
    alert_id: str
    verdict: str  # true_positive, false_positive, needs_investigation
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    risk_score: float = 0.0
    mitre_techniques: List[str] = []
    recommended_actions: List[ActionSuggestion] = []
    grounded_by: List[str] = []  # log_event IDs used as evidence
    timeline_events: List[str] = []


class TimelineEvent(BaseModel):
    """Single event in an attack timeline."""
    timestamp: str
    event_type: str
    description: str
    severity: str = "INFO"
    log_event_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_anomalous: bool = False
