from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScanMode = Literal["standard", "advanced"]


class ScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, description="Dominios o URLs a evaluar")
    institution: str | None = None
    mode: ScanMode = "standard"
    custom_paths: list[str] = Field(default_factory=list)
    include_default_paths: bool = True


class ScanResultOut(BaseModel):
    id: int
    domain: str
    url_evaluated: str
    final_url: str | None
    http_code: int
    response_type: str
    redirect_chain: list[dict]
    scanned_at: datetime
    headers: dict[str, str]
    missing_headers: list[str]
    cookies: list[dict]
    score: float
    grade: int
    is_scoring_source: bool
    evidence: dict
    notes: str | None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    institution: str | None
    domain: str
    mode: str
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
    tls_evidence: dict | None = None
    dns_evidence: dict | None = None
    results: list[ScanResultOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    institution: str | None
    domain: str
    mode: str
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

    model_config = {"from_attributes": True}


class DashboardFilters(BaseModel):
    search: str | None = None
    grade: int | None = None
    comparison_status: str | None = None
    mode: str | None = None
