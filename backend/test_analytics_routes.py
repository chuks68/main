"""Tests for the analytics Flask blueprint routes.

Exercises `register_analytics_routes` end to end with the Flask test client.
"""

import json
import pytest
from flask import Flask

from backend.analytics import routes as analytics_routes


@pytest.fixture()
def app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True

    # Register routes against a test engine. The engine is provided by the
    # analytics module's test helpers; reset_all_for_tests ensures isolation.
    analytics_routes.reset_all_for_tests()
    analytics_routes.set_engine(analytics_routes.make_test_engine())

    analytics_routes.register_analytics_routes(flask_app)

    yield flask_app

    analytics_routes.reset_all_for_tests()


@pytest.fixture()
def client(app):
    return app.test_client()


def _registered_rules(app):
    """Return the analytics route rules registered on the app."""
    return [
        rule
        for rule in app.url_map.iter_rules()
        if rule.endpoint.startswith("analytics")
    ]


def _envelope_keys():
    """Keys that every analytics response envelope is expected to contain."""
    return {"ok", "data", "error"}


def _assert_envelope(payload):
    assert isinstance(payload, dict), f"expected dict envelope, got {type(payload)!r}"
    keys = set(payload.keys())
    # Envelope must at least expose an ok flag and a data/error slot.
    assert "ok" in keys, f"missing 'ok' in envelope: {keys}"
    assert keys & {"data", "error"}, f"envelope missing data/error: {keys}"


def _assert_no_raw_config(payload):
    """Responses must not include raw config values beyond safe summaries."""
    serialized = json.dumps(payload, default=str).lower()
    forbidden = [
        "secret",
        "password",
        "api_key",
        "apikey",
        "token",
        "private_key",
        "database_url",
        "dsn",
    ]
    for needle in forbidden:
        assert needle not in serialized, (
            f"response leaked raw config value matching {needle!r}: {serialized}"
        )


def test_routes_are_registered(app):
    rules = _registered_rules(app)
    assert rules, "register_analytics_routes did not register any routes"


def test_every_route_has_success_and_failure(client, app):
    """Every registered route must respond to a valid and an invalid request."""
    rules = _registered_rules(app)
    assert rules, "no analytics routes registered"

    for rule in rules:
        path = rule.rule
        methods = sorted(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})
        assert methods, f"route {path} exposes no testable methods"

        for method in methods:
            # Success case: empty/valid payload.
            success = client.open(path, method=method, json={})
            assert success.status_code < 500, (
                f"{method} {path} returned server error on valid payload: "
                f"{success.status_code}"
            )
            if success.is_json:
                _assert_envelope(success.get_json())
                _assert_no_raw_config(success.get_json())

            # Failure case: malformed payload.
            failure = client.open(
                path,
                method=method,
                data="{not-json",
                content_type="application/json",
            )
            assert failure.status_code >= 400, (
                f"{method} {path} accepted malformed payload: "
                f"{failure.status_code}"
            )
            if failure.is_json:
                _assert_envelope(failure.get_json())
                _assert_no_raw_config(failure.get_json())


def test_safe_feature_flags_summary(client, app):
    """Feature flag responses expose only the safe summary, not raw values."""
    rules = _registered_rules(app)
    flag_rules = [r for r in rules if "flag" in r.rule.lower()]
    if not flag_rules:
        pytest.skip("no feature-flag route registered")

    for rule in flag_rules:
        resp = client.get(rule.rule)
        assert resp.status_code < 500
        if resp.is_json:
            payload = resp.get_json()
            _assert_envelope(payload)
            _assert_no_raw_config(payload)


def test_safe_limits_summary(client, app):
    """Limits responses expose only the safe summary, not raw values."""
    rules = _registered_rules(app)
    limit_rules = [r for r in rules if "limit" in r.rule.lower()]
    if not limit_rules:
        pytest.skip("no limits route registered")

    for rule in limit_rules:
        resp = client.get(rule.rule)
        assert resp.status_code < 500
        if resp.is_json:
            payload = resp.get_json()
            _assert_envelope(payload)
            _assert_no_raw_config(payload)


def test_engine_reset_between_tests(app):
    """reset_all_for_tests must clear engine state between tests."""
    # First test body: mutate engine state via a request.
    client = app.test_client()
    rules = _registered_rules(app)
    if rules:
        client.get(rules[0].rule)

    # Reset and confirm the module reports a clean state.
    analytics_routes.reset_all_for_tests()
    assert analytics_routes.get_engine() is None
