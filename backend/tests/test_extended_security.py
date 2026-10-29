import pytest

from app.checks import check_engine
from app.config import settings
from app.policy import enforce_policy, load_policy
from app.scan_service import execute_scan_request
from app.scanner import authorized_checks
from app.scanner.dependency_intel import extract_js_components
from app.schemas import ScanRequest


def test_extended_passive_checks_redact_secret_values():
    result = {
        "url_evaluated": "https://example.com/",
        "path": "/",
        "http_code": 200,
        "headers": {
            "content-security-policy": "script-src * 'unsafe-eval'",
            "strict-transport-security": "max-age=300",
            "cross-origin-resource-policy": "cross-origin",
        },
        "cookies": [
            {
                "name": "__Host-session",
                "secure": False,
                "domain": "example.com",
                "path": "/app",
                "samesite": "None",
                "max_age": "63072000",
            }
        ],
        "body_preview": (
            '<script src="https://cdn.example.net/app.js"></script>'
            '<script>const apiKey="AKIAAAAAAAAAAAAAAAAA";</script>'
        ),
    }
    findings = check_engine.run(result)
    by_id = {finding["id"]: finding for finding in findings}
    assert "weak_csp" in by_id
    assert "hsts_not_preload_ready" in by_id
    assert "external_assets_without_sri" in by_id
    assert "public_secret_pattern" in by_id
    assert "AKIA" not in str(by_id["public_secret_pattern"]["evidence"])
    assert any(check_id.startswith("cookie_policy_") for check_id in by_id)


def test_policy_rejects_rate_above_declared_limit():
    load_policy.cache_clear()
    request = ScanRequest(
        domains=["example.com"],
        authorization_confirmed=True,
        requests_per_second=5,
    )
    with pytest.raises(ValueError, match="velocidad"):
        enforce_policy(request)


@pytest.mark.asyncio
async def test_authorized_request_cannot_run_on_passive_worker(monkeypatch):
    monkeypatch.setattr(settings, "authorized_worker", False)
    request = ScanRequest(
        domains=["example.com"],
        authorization_confirmed=True,
        execution_mode="authorized",
        active_authorization_confirmed=True,
        authorization_reference="scope-123",
        active_checks=["reflection"],
    )
    with pytest.raises(ValueError, match="worker aislado"):
        await execute_scan_request(request, None)


@pytest.mark.asyncio
async def test_authorized_reflection_uses_marker_without_executable_payload(monkeypatch):
    async def fake_fetch(url, **kwargs):
        marker = url.split("geeknosy_probe=")[1]
        return {"body_preview": marker, "headers": {}, "http_code": 200}

    monkeypatch.setattr(authorized_checks, "fetch_path", fake_fetch)
    findings = await authorized_checks.run_authorized_checks(
        "example.com", ["reflection"], requests_per_second=1
    )
    assert [finding["id"] for finding in findings] == ["input_reflected_unencoded"]
    assert findings[0]["intrusiveness"] == "authorized-low-impact"


def test_javascript_inventory_extracts_named_versions_only():
    components = extract_js_components(
        '<script src="/assets/jquery-3.4.1.min.js"></script>'
        '<script src="/assets/app.8f3c1.js"></script>'
    )
    assert components == [
        {"package": "jquery", "version": "3.4.1", "source": "/assets/jquery-3.4.1.min.js"}
    ]
