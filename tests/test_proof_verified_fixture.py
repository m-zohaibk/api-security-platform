import json
from pathlib import Path


FIXTURE = Path(__file__).resolve().parents[1] / "datasets" / "fixtures" / "proof_verified_regression_cases.json"


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_proof_verified_fixture_is_sanitized_and_nonempty():
    fixture = load_fixture()
    assert fixture["purpose"].startswith("Regression evidence only")
    assert fixture["cases"]
    assert all("http" not in json.dumps(case).lower() for case in fixture["cases"])
    assert all("response_body" not in case for case in fixture["cases"])


def test_fixture_cases_have_independent_agreement():
    cases = load_fixture()["cases"]
    assert all(case["manual_verified"] and case["scanner_verified"] for case in cases)
    assert all(case["label"] in {0, 1} for case in cases)
    assert all((case["label_name"] == "confirmed") == (case["label"] == 1) for case in cases)


def test_fixture_has_positive_and_negative_controls():
    cases = load_fixture()["cases"]
    assert any(case["label"] == 1 for case in cases)
    assert any(case["label"] == 0 for case in cases)
    assert any(case["label_name"] == "not_applicable" for case in cases)
