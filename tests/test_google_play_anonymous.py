from __future__ import annotations

from types import SimpleNamespace
from typing import ClassVar

import pytest

from apkworkbench.sources import google_play_anonymous as auth


def _auth_payload(
    token: str = "anonymous-play-bearer",
    *,
    gsf_id: str = "1234567890",
) -> dict:
    return {
        "authToken": token,
        "gsfId": gsf_id,
        "deviceCheckInConsistencyToken": "checkin-consistency",
        "deviceConfigToken": "device-config",
        "dfeCookie": "dfe-cookie",
        "deviceInfoProvider": {
            "userAgentString": "Android-Finsky/test (api=3,device=test)",
            "mccMnc": "310260",
        },
    }


class FakePlayApi:
    calls: ClassVar[list] = []

    def __init__(self, device, session):
        self.device = device
        self.session = session
        self.profile = SimpleNamespace(
            props={"CellOperator": "000000"},
            user_agent=lambda: "fallback-user-agent",
            device_config=lambda: b"device-config",
        )
        self._http = SimpleNamespace(close=lambda: None)
        type(self).calls.append(self)


@pytest.fixture(autouse=True)
def no_account_environment(monkeypatch):
    monkeypatch.delenv("GOOPDL_ACCOUNT_EMAIL", raising=False)
    monkeypatch.delenv("GOOPDL_AAS_TOKEN", raising=False)
    FakePlayApi.calls.clear()


def test_uses_anonymous_dispenser_session_and_matches_device_headers(monkeypatch):
    payload = _auth_payload()
    monkeypatch.setattr(auth, "PlayApi", FakePlayApi)
    seen_options = {}

    def pick_token(**kwargs):
        seen_options.update(kwargs)
        return payload

    monkeypatch.setattr(auth.token_auth, "pick_pool_token", pick_token)

    session = auth.AnonymousGooglePlaySession(country="US")
    api = session.new_api()

    assert api.device["gsfId"] == "1234567890"
    assert api.device["deviceCheckinConsistencyToken"] == "checkin-consistency"
    assert "deviceCheckInConsistencyToken" not in api.device
    assert api.device["locale"] == "en_US"
    assert api.session == {
        "authToken": "anonymous-play-bearer",
        "deviceConfigToken": "device-config",
        "dfeCookie": "dfe-cookie",
    }
    assert api.profile.user_agent() == "Android-Finsky/test (api=3,device=test)"
    assert api.profile.props["CellOperator"] == "310260"
    assert seen_options["country"] == "US"


def test_default_anonymous_session_does_not_force_dispenser_country(monkeypatch):
    payload = _auth_payload()
    seen_options = {}

    def pick_token(**kwargs):
        seen_options.update(kwargs)
        return payload

    monkeypatch.setattr(auth, "PlayApi", FakePlayApi)
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", pick_token)

    api = auth.AnonymousGooglePlaySession().new_api()

    assert "country" not in seen_options
    # Preserve the established English/US Play catalogue locale without
    # rewriting each anonymous device profile's registered country.
    assert api.device["locale"] == "en_US"


def test_401_replaces_the_rejected_anonymous_token(monkeypatch):
    first = _auth_payload("first-bearer")
    second = _auth_payload("replacement-bearer", gsf_id="9876543210")
    monkeypatch.setattr(auth, "PlayApi", FakePlayApi)
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", lambda **_kwargs: first)
    replaced = {}

    def replace(failed_token, **_kwargs):
        replaced["failed"] = failed_token
        return second

    monkeypatch.setattr(auth.token_auth, "replace_pool_token", replace)
    session = auth.AnonymousGooglePlaySession()

    first_api = session.new_api()
    second_api = session.new_api(force_refresh=True)

    assert first_api.session["authToken"] == "first-bearer"
    assert second_api.session["authToken"] == "replacement-bearer"
    assert second_api.device["gsfId"] == "9876543210"
    assert replaced["failed"] is first


@pytest.mark.parametrize("name,value", [
    ("GOOPDL_ACCOUNT_EMAIL", "research@example.invalid"),
    ("GOOPDL_AAS_TOKEN", "aas_et/not-used"),
])
def test_refuses_to_fall_back_to_user_account_credentials(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    called = []
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", lambda **_kwargs: called.append(True))

    with pytest.raises(auth.AnonymousGooglePlaySessionError, match="anonymous Play access only"):
        auth.AnonymousGooglePlaySession(auth_mode="anonymous").new_api()

    assert called == []


def test_auto_mode_uses_account_credentials_from_the_environment(monkeypatch):
    monkeypatch.setenv("GOOPDL_ACCOUNT_EMAIL", "research@example.invalid")
    monkeypatch.setenv("GOOPDL_AAS_TOKEN", "aas_et/session-token")
    payload = _auth_payload("account-bearer", gsf_id="424242")
    monkeypatch.setattr(auth, "PlayApi", FakePlayApi)
    seen = {}

    def pick_token(**kwargs):
        seen["kwargs"] = kwargs
        return payload

    original_use_scope = auth.token_auth._use_scope

    def use_scope(scope):
        seen["credentials"] = scope.credentials
        return original_use_scope(scope)

    monkeypatch.setattr(auth.token_auth, "_use_scope", use_scope)
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", pick_token)

    fake = FakePlayApi
    fake.calls.clear()
    api = auth.GooglePlaySession(auth_mode="auto", load_saved_account=lambda: None).new_api()

    assert seen["credentials"] == ("research@example.invalid", "aas_et/session-token")
    assert api.session["authToken"] == "account-bearer"
    assert api.device["gsfId"] == "424242"


def test_auto_mode_falls_back_to_the_dispenser_without_account(monkeypatch):
    monkeypatch.delenv("GOOPDL_ACCOUNT_EMAIL", raising=False)
    monkeypatch.delenv("GOOPDL_AAS_TOKEN", raising=False)
    payload = _auth_payload("anonymous-bearer")
    monkeypatch.setattr(auth, "PlayApi", FakePlayApi)
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", lambda **_kwargs: payload)

    api = auth.GooglePlaySession(auth_mode="auto", load_saved_account=lambda: None).new_api()

    assert api.session["authToken"] == "anonymous-bearer"


def test_account_mode_without_any_credentials_fails_with_remedy(monkeypatch):
    called = []
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", lambda **_kwargs: called.append(True))

    with pytest.raises(auth.AnonymousGooglePlaySessionError, match="goopdl auth login"):
        auth.GooglePlaySession(auth_mode="account", load_saved_account=lambda: None).new_api()

    assert called == []


def test_account_mode_prefers_saved_account_over_nothing_and_masks_doctor_report(monkeypatch):
    report = auth.describe_auth_mode(
        "auto",
        load_saved_account=lambda: ("researcher@example.invalid", "aas_et/x"),
    )
    assert report["resolved_mode"] == "account"
    assert report["account_source"] == "goopdl_saved_account"
    assert report["account_email"] == "r***@example.invalid"

    report_env = auth.describe_auth_mode(
        "auto",
        load_saved_account=lambda: ("saved@example.invalid", "aas_et/y"),
        read_env=lambda: ("env@example.invalid", "aas_et/z"),
    )
    assert report_env["account_source"] == "environment"
    assert report_env["account_email"] == "e***@example.invalid"

    report_none = auth.describe_auth_mode("auto", load_saved_account=lambda: None)
    assert report_none["resolved_mode"] == "anonymous"

    report_account = auth.describe_auth_mode("account", load_saved_account=lambda: None)
    assert report_account["resolved_mode"] is None


def test_session_error_carries_dispenser_retry_after_hint(monkeypatch):
    failure = auth.token_auth.DispenserRateLimitedError(120)

    def fail(**_kwargs):
        raise failure

    monkeypatch.setattr(auth.token_auth, "pick_pool_token", fail)
    with pytest.raises(auth.AnonymousGooglePlaySessionError) as raised:
        auth.GooglePlaySession(
            auth_mode="auto", load_saved_account=lambda: None
        ).new_api()

    assert raised.value.retry_after == 120


def test_rejects_invalid_country_code():
    with pytest.raises(ValueError, match="two-letter"):
        auth.AnonymousGooglePlaySession(country="United States")


def test_google_play_source_delegates_session_creation_to_anonymous_provider():
    from apkworkbench.sources.google_play import GooglePlaySource

    class FakeAnonymousSession:
        def __init__(self):
            self.refresh_calls = []

        def new_api(self, *, force_refresh=False):
            self.refresh_calls.append(force_refresh)
            return object()

    provider = FakeAnonymousSession()
    source = GooglePlaySource(anonymous_session=provider)

    first = source._new_api()
    renewed = source._new_api(force_session=True)

    assert first is not None
    assert renewed is not None
    assert provider.refresh_calls == [False, True]


def test_dispenser_failure_preserves_safe_status_and_reason(monkeypatch):
    failure = auth.token_auth.DispenserUnavailableError(503, reason="server")

    def fail(**_kwargs):
        raise failure

    monkeypatch.setattr(auth.token_auth, "pick_pool_token", fail)
    with pytest.raises(auth.AnonymousGooglePlaySessionError) as raised:
        auth.AnonymousGooglePlaySession().new_api()

    message = str(raised.value)
    assert "DispenserUnavailableError" in message
    assert "HTTP 503" in message
    assert "reason=server" in message
    assert "api/auth" not in message


def test_dispenser_rate_limit_preserves_retry_after_without_credentials(monkeypatch):
    failure = auth.token_auth.DispenserRateLimitedError(120)

    def fail(**_kwargs):
        raise failure

    monkeypatch.setattr(auth.token_auth, "pick_pool_token", fail)
    with pytest.raises(auth.AnonymousGooglePlaySessionError) as raised:
        auth.AnonymousGooglePlaySession().new_api()

    message = str(raised.value)
    assert "HTTP 429" in message
    assert "retry_after=120s" in message


def test_unexpected_dispenser_error_text_is_not_exposed(monkeypatch):
    secret_message = "Authorization: Bearer do-not-log-me https://auroraoss.com/api/auth"

    def fail(**_kwargs):
        raise RuntimeError(secret_message)

    monkeypatch.setattr(auth.token_auth, "pick_pool_token", fail)
    with pytest.raises(auth.AnonymousGooglePlaySessionError) as raised:
        auth.AnonymousGooglePlaySession().new_api()

    message = str(raised.value)
    assert "RuntimeError" in message
    assert "do-not-log-me" not in message
    assert "auroraoss.com" not in message
