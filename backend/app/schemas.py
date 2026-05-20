from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScanMode = Literal["standard", "advanced"]
RouteProfile = Literal["auto", "minimal", "standard", "advanced", "all"]


class ScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, description="Dominios o URLs a evaluar")
    institution: str | None = None
    mode: ScanMode = "standard"
    route_profile: RouteProfile = "auto"
    custom_paths: list[str] = Field(default_factory=list)
    include_default_paths: bool = True
    include_exposure_checks: bool = False
    max_paths_per_domain: int = Field(default=40, ge=1, le=120)


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
