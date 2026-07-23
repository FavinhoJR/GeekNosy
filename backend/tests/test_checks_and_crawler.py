from app.checks import check_engine
from app.scanner.crawler import discover_same_origin_paths


def test_passive_check_engine_detects_semantic_issues():
    result = {
        "url_evaluated": "https://example.com/login",
        "path": "/login",
        "http_code": 200,
        "headers": {
            "content-security-policy": "default-src *; script-src 'unsafe-inline'",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "server": "nginx/1.27.0",
        },
        "body_preview": "",
    }
    findings = check_engine.run(result)
    ids = {finding["id"] for finding in findings}
    assert {"weak_csp", "cors_wildcard_credentials", "server_version_exposed"} <= ids
    assert all(finding["fingerprint"] for finding in findings)


def test_crawler_stays_same_origin_and_strips_query_values():
    html = """
    <a href="/account?id=secret&view=full">Account</a>
    <a href="https://evil.example/path">Outside</a>
    <form action="/login"></form>
    """
    paths = discover_same_origin_paths("https://example.com/", html)
    assert "/account?id=&view=" in paths
    assert "/login" in paths
    assert all("evil.example" not in path for path in paths)
