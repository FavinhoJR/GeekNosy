from types import SimpleNamespace

import pytest

from app.database import async_session, init_db
from app.scan_service import execute_scan_request
from app.schemas import ScanRequest


@pytest.mark.asyncio
async def test_persists_scan_and_initialized_results_without_lazy_loading(monkeypatch):
    async def fake_target(_raw):
        return SimpleNamespace(hostname="8.8.8.8", port=443)

    async def fake_scan(**_kwargs):
        return {
            "overall_score": 80.0,
            "overall_grade": 8,
            "scoring_url": "https://8.8.8.8/",
            "scoring_http_code": 200,
            "tls_score": 80.0,
            "headers_score": 80.0,
            "cookies_score": 100.0,
            "dns_score": 80.0,
            "consistency_score": 100.0,
            "findings": [],
            "finding_details": [],
            "tls_evidence": {"valid": True},
            "dns_evidence": {"a_records": ["8.8.8.8"]},
            "route_profile": "minimal",
            "include_exposure_checks": False,
            "max_paths_per_domain": 8,
            "tech_detection": {},
            "route_selection": {},
            "results": [
                {
                    "url_evaluated": "https://8.8.8.8/",
                    "final_url": "https://8.8.8.8/",
                    "http_code": 200,
                    "response_type": "main",
                    "headers": {},
                    "missing_headers": [],
                    "cookies": [],
                    "redirect_chain": [],
                    "score": 80,
                    "grade": 8,
                    "is_scoring_source": True,
                    "path": "/",
                    "profile": "core",
                    "evidence": {},
                }
            ],
        }

    monkeypatch.setattr("app.scan_service.normalize_and_validate_domain", fake_target)
    monkeypatch.setattr("app.scan_service.run_full_scan", fake_scan)
    await init_db()
    async with async_session() as session:
        scans = await execute_scan_request(
            ScanRequest(
                domains=["8.8.8.8"],
                authorization_confirmed=True,
                intensity="passive",
                route_profile="minimal",
                max_paths_per_domain=8,
            ),
            session,
            owner="test-owner",
        )
        await session.commit()
        assert len(scans) == 1
        assert len(scans[0].results) == 1
        assert scans[0].results[0].is_scoring_source is True
