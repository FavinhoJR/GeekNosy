import pytest

from app.scanner.route_selector import select_route_profiles
from app.scanner.scoring import compute_overall_score, score_cookies, score_to_grade


def test_score_boundaries_and_weights():
    assert score_to_grade(0) == 1
    assert score_to_grade(100) == 10
    assert compute_overall_score("standard", 100, 100, https_redirect=True) == 100
    assert compute_overall_score("standard", 100, 100, https_redirect=False) < 100


def test_cookie_score_and_route_cap():
    score, findings = score_cookies(
        [{"name": "session", "secure": False, "httponly": True, "samesite": None}]
    )
    assert score == pytest.approx(100 / 3)
    assert {"cookie_no_secure", "cookie_no_samesite"} <= set(findings)

    selected = select_route_profiles(
        "all", "advanced", [], True, True, ["/custom"], max_paths=10
    )
    assert selected["total_selected"] == 10
