import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    institution: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    mode: Mapped[str] = mapped_column(String(32), default="standard")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    overall_grade: Mapped[int] = mapped_column(Integer, default=1)
    scoring_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    scoring_http_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    comparison_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    score_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    previous_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_score: Mapped[float] = mapped_column(Float, default=0.0)
    headers_score: Mapped[float] = mapped_column(Float, default=0.0)
    cookies_score: Mapped[float] = mapped_column(Float, default=0.0)
    dns_score: Mapped[float] = mapped_column(Float, default=0.0)
    consistency_score: Mapped[float] = mapped_column(Float, default=0.0)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    route_profile: Mapped[str | None] = mapped_column(String(32), nullable=True)
    include_exposure_checks: Mapped[bool] = mapped_column(default=False)
    max_paths_per_domain: Mapped[int | None] = mapped_column(Integer, nullable=True)
    route_meta_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    intensity: Mapped[str] = mapped_column(String(32), default="standard")
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    finding_details_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def set_findings(self, findings: list[str]):
        self.findings_json = json.dumps(findings)

    def get_findings(self) -> list[str]:
        if not self.findings_json:
            return []
        return json.loads(self.findings_json)

    def set_route_meta(self, tech: dict, selection: dict):
        self.route_meta_json = json.dumps(
            {"tech_detection": tech, "route_selection": selection},
            ensure_ascii=False,
        )

    def get_route_meta(self) -> dict:
        if not self.route_meta_json:
            return {}
        return json.loads(self.route_meta_json)

    def set_finding_details(self, details: list[dict]):
        self.finding_details_json = json.dumps(details, ensure_ascii=False, default=str)

    def get_finding_details(self) -> list[dict]:
        return json.loads(self.finding_details_json) if self.finding_details_json else []


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    url_evaluated: Mapped[str] = mapped_column(String(2048))
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    http_code: Mapped[int] = mapped_column(Integer, default=0)
    response_type: Mapped[str] = mapped_column(String(32), default="unknown")
    redirect_chain_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    headers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    missing_headers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cookies_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    grade: Mapped[int] = mapped_column(Integer, default=1)
    is_scoring_source: Mapped[bool] = mapped_column(default=False)
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="results")

    def set_headers(self, headers: dict):
        self.headers_json = json.dumps(headers, ensure_ascii=False)

    def get_headers(self) -> dict:
        if not self.headers_json:
            return {}
        return json.loads(self.headers_json)

    def set_missing_headers(self, missing: list[str]):
        self.missing_headers_json = json.dumps(missing)

    def get_missing_headers(self) -> list[str]:
        if not self.missing_headers_json:
            return []
        return json.loads(self.missing_headers_json)

    def set_redirect_chain(self, chain: list[dict]):
        self.redirect_chain_json = json.dumps(chain, ensure_ascii=False)

    def get_redirect_chain(self) -> list[dict]:
        if not self.redirect_chain_json:
            return []
        return json.loads(self.redirect_chain_json)

    def set_evidence(self, evidence: dict):
        self.evidence_json = json.dumps(evidence, ensure_ascii=False)

    def get_evidence(self) -> dict:
        if not self.evidence_json:
            return {}
        return json.loads(self.evidence_json)

    def set_cookies(self, cookies: list[dict]):
        self.cookies_json = json.dumps(cookies, ensure_ascii=False)

    def get_cookies(self) -> list[dict]:
        if not self.cookies_json:
            return []
        return json.loads(self.cookies_json)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    phase: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_json: Mapped[str] = mapped_column(Text)
    scan_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def set_request(self, value: dict):
        self.request_json = json.dumps(value, ensure_ascii=False)

    def get_request(self) -> dict:
        return json.loads(self.request_json)

    def set_scan_ids(self, value: list[int]):
        self.scan_ids_json = json.dumps(value)

    def get_scan_ids(self) -> list[int]:
        return json.loads(self.scan_ids_json) if self.scan_ids_json else []


class FindingTriage(Base):
    __tablename__ = "finding_triage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), index=True)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="new")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(255))
    request_json: Mapped[str] = mapped_column(Text)
    interval_minutes: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def set_request(self, value: dict):
        self.request_json = json.dumps(value, ensure_ascii=False)

    def get_request(self) -> dict:
        return json.loads(self.request_json)
