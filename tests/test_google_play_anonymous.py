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
    monkeypatch.setattr(auth.token_auth, "pick_pool_token", lambda **_kwargs: payload)

    session = auth.AnonymousGooglePlaySession(country="US")
    api = session.new_api()

    assert api.device["gsfId"] == "1234567890"
    assert api.device["deviceCheckInConsistencyToken"] == "checkin-consistency"
    assert api.device["locale"] == "en_US"
    assert api.session == {
        "authToken": "anonymous-play-bearer",
        "deviceConfigToken": "device-config",
        "dfeCookie": "dfe-cookie",
    }
    assert api.profile.user_agent() == "Android-Finsky/test (api=3,device=test)"
    assert api.profile.props["CellOperator"] == "310260"


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
        auth.AnonymousGooglePlaySession().new_api()

    assert called == []


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
