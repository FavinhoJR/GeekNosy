from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ScanMode = Literal["standard", "advanced"]
RouteProfile = Literal["auto", "minimal", "standard", "advanced", "all"]
ScanIntensity = Literal["passive", "fast", "standard", "bug_bounty", "deep", "custom"]


class ScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, description="Dominios o URLs a evaluar")
    institution: str | None = None
    mode: ScanMode = "standard"
    route_profile: RouteProfile = "auto"
    custom_paths: list[str] = Field(default_factory=list)
    include_default_paths: bool = True
    include_exposure_checks: bool = False
    max_paths_per_domain: int = Field(default=40, ge=1, le=120)
    intensity: ScanIntensity = "standard"
    authorization_confirmed: bool = False
    requests_per_second: float | None = Field(default=None, ge=0.2, le=50)
    tags: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("domains")
    @classmethod
    def clean_domains(cls, domains: list[str]) -> list[str]:
        cleaned = [domain.strip() for domain in domains if domain.strip()]
        if not cleaned:
            raise ValueError("Debe indicar al menos un dominio")
        return list(dict.fromkeys(cleaned))

    @field_validator("custom_paths")
    @classmethod
    def validate_paths(cls, paths: list[str]) -> list[str]:
        result = []
        for path in paths:
            value = path.strip()
            if not value:
                continue
            if "://" in value or value.startswith("//"):
                raise ValueError("Las rutas personalizadas deben ser relativas al dominio")
            if not value.startswith("/"):
                value = "/" + value
            result.append(value)
        return list(dict.fromkeys(result))


class ScanJobCreate(BaseModel):
    request: ScanRequest


class ScanJobOut(BaseModel):
    id: str
    status: str
    progress: float
    phase: str | None = None
    owner: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancel_requested: bool = False
    error: str | None = None
    scan_ids: list[int] = []
    request: dict


class FindingTriageUpdate(BaseModel):
    status: Literal["new", "confirmed", "false_positive", "accepted", "resolved"]
    notes: str | None = Field(default=None, max_length=4000)


class FindingOut(BaseModel):
    id: str
    fingerprint: str
    title: str
    severity: str
    confidence: str = "medium"
    status: str = "new"
    notes: str | None = None
    recommendation: str = ""
    references: list[str] = []
    evidence: dict = {}


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    interval_minutes: int = Field(ge=5, le=525600)
    request: ScanRequest


class ScheduleUpdate(BaseModel):
    enabled: bool


class ScheduleOut(BaseModel):
    id: str
    name: str
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None = None
    created_at: datetime
    request: dict


class ScanResultOut(BaseModel):
    id: int
    domain: str
    path: str
    profile: str
    url_evaluated: str
    final_url: str | None
    http_code: int
    response_type: str
    redirect_chain: list[dict]
    scanned_at: datetime
    headers: dict[str, str]
    missing_headers: list[str]
    present_headers: list[str] = []
    cookies: list[dict]
    content_type: str | None = None
    content_length: int | None = None
    severity: str | None = None
    finding_key: str | None = None
    score: float
    grade: int
    is_scoring_source: bool
    evidence: dict
    notes: str | None
    recommendation: dict | None = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    institution: str | None
    domain: str
    mode: str
    intensity: str = "standard"
    job_id: str | None = None
    route_profile: str | None = None
    include_exposure_checks: bool = False
    max_paths_per_domain: int | None = None
    created_at: datetime
    overall_score: float
    overall_grade: int
    scoring_url: str | None
    scoring_http_code: int | None
    comparison_status: str | None
    score_delta: float | None
    previous_score: float | None
    score_explanation: str | None
    tls_score: float
    headers_score: float
    cookies_score: float
    dns_score: float
    consistency_score: float
    findings: list[str]
    finding_details: list[dict] = []
    recommendations: list[dict]
    tech_detection: dict | None = None
    route_selection: dict | None = None
    tls_evidence: dict | None = None
    dns_evidence: dict | None = None
    results: list[ScanResultOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    institution: str | None
    domain: str
    mode: str
    intensity: str = "standard"
    job_id: str | None = None
    route_profile: str | None = None
    created_at: datetime
    overall_score: float
    overall_grade: int
    scoring_url: str | None
    scoring_http_code: int | None
    comparison_status: str | None
    score_delta: float | None
    previous_score: float | None
    scoring_source_type: str | None = None
    header_checks: dict[str, bool] = {}
    cookies_ok: bool | None = None
    tls_ok: bool | None = None
    paths_evaluated_count: int | None = None

    model_config = {"from_attributes": True}
