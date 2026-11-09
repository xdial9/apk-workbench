"""Anonymous Google Play FDFE session adapter.

The Google Play internal API requires a short-lived bearer token. This module
obtains one without a user Google account, AAS token, or API key by using the
public Aurora Store token dispenser through goopdl. The existing
playstore-cli PlayApi remains responsible for categories, search, charts,
delivery metadata, and downstream downloads.
"""
from __future__ import annotations

import math
import os
import re
from typing import Any

from goopdl import auth as token_auth
from playstore_cli.api import PlayApi
from playstore_cli.device import DEFAULT_PROFILE


class AnonymousGooglePlaySessionError(RuntimeError):
    """Raised when an anonymous Play API session cannot be obtained."""


def _safe_exception_summary(exc: Exception) -> str:
    """Preserve typed, non-secret failure details without exposing request data."""
    parts = [type(exc).__name__]
    status = getattr(exc, "status", None)
    if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
        parts.append(f"HTTP {status}")
    reason = getattr(exc, "reason", None)
    if reason in {"transport", "server", "profile_rejected"}:
        parts.append(f"reason={reason}")
    stage = getattr(exc, "stage", None)
    if stage in {"auth", "checkin", "toc"}:
        parts.append(f"stage={stage}")
    retry_after = getattr(exc, "retry_after", None)
    if isinstance(retry_after, (int, float)) and not isinstance(retry_after, bool):
        if math.isfinite(retry_after) and 0 <= retry_after <= 3600:
            parts.append(f"retry_after={retry_after:g}s")
    return "; ".join(parts)


class _ProfileView:
    """Expose the profile methods PlayApi needs, using the dispenser-issued device."""

    def __init__(self, fallback: Any, device_info: dict[str, Any]) -> None:
        self._fallback = fallback
        self.props = dict(getattr(fallback, "props", {}) or {})
        mcc_mnc = str(device_info.get("mccMnc") or "").strip()
        if mcc_mnc:
            self.props["CellOperator"] = mcc_mnc
        self._user_agent = (
            str(device_info.get("userAgentString") or "").strip()
            or fallback.user_agent()
        )

    def user_agent(self) -> str:
        return self._user_agent

    def device_config(self):
        return self._fallback.device_config()


class AnonymousGooglePlaySession:
    """Create PlayApi instances backed by anonymously-issued device sessions.

    No Google account is read. A short-lived bearer token is obtained from
    Aurora's public dispenser and cached/rotated by goopdl. The bearer remains
    in memory here; goopdl owns its private token cache.
    """

    def __init__(
        self,
        *,
        arch: str = "arm64",
        country: str = "US",
        profile: str | None = None,
        dispenser_url: str | None = None,
    ) -> None:
        country = (country or "US").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("country must be a two-letter ISO country code")
        self.arch = arch
        self.country = country
        self.profile = profile
        self.dispenser_url = dispenser_url
        self._auth: dict[str, Any] | None = None
        self._api: PlayApi | None = None

    @staticmethod
    def _require_anonymous_environment() -> None:
        # Fail closed rather than silently using a user's saved Google account
        # when goopdl's optional account-mode environment is present.
        account_vars = (
            "GOOPDL_ACCOUNT_EMAIL",
            "GOOPDL_AAS_TOKEN",
        )
        configured = [name for name in account_vars if os.environ.get(name, "").strip()]
        if configured:
            raise AnonymousGooglePlaySessionError(
                "APK Workbench is configured for anonymous Play access only. "
                "Unset GOOPDL_ACCOUNT_EMAIL and GOOPDL_AAS_TOKEN; no Google "
                "account token is read or used."
            )

    def _token_options(self) -> dict[str, Any]:
        options: dict[str, Any] = {
            "arch": self.arch,
            "country": self.country,
            "raise_on_error": True,
        }
        if self.profile:
            options["profile"] = self.profile
        if self.dispenser_url:
            options["dispenser_url"] = self.dispenser_url
        return options

    def _get_auth(self, *, force_refresh: bool) -> dict[str, Any]:
        options = self._token_options()
        if force_refresh and self._auth is not None:
            auth_data = token_auth.replace_pool_token(self._auth, **options)
        else:
            auth_data = token_auth.pick_pool_token(**options)
        if not isinstance(auth_data, dict):
            raise AnonymousGooglePlaySessionError(
                "Aurora's public token dispenser did not return an anonymous Play session."
            )
        if not auth_data.get("authToken") or not auth_data.get("gsfId"):
            raise AnonymousGooglePlaySessionError(
                "The anonymous Play session response is missing required device credentials."
            )
        return auth_data

    def new_api(self, *, force_refresh: bool = False) -> PlayApi:
        """Return a PlayApi using an anonymous dispenser token, refreshing after 401."""
        self._require_anonymous_environment()
        try:
            auth_data = self._get_auth(force_refresh=force_refresh)
            device = {
                # PlayApi loads this profile during construction. Its UA and
                # operator fields are immediately replaced by the matching
                # dispenser-issued device information below.
                "profile": DEFAULT_PROFILE,
                "gsfId": str(auth_data["gsfId"]),
                "deviceCheckInConsistencyToken": str(
                    auth_data.get("deviceCheckInConsistencyToken") or ""
                ),
                "locale": f"en_{self.country}",
            }
            session = {
                "authToken": str(auth_data["authToken"]),
                "deviceConfigToken": str(auth_data.get("deviceConfigToken") or ""),
                "dfeCookie": str(auth_data.get("dfeCookie") or ""),
            }
            api = PlayApi(device, session)
            device_info = auth_data.get("deviceInfoProvider")
            if not isinstance(device_info, dict):
                device_info = {}
            api.profile = _ProfileView(api.profile, device_info)

            previous = self._api
            self._auth = auth_data
            self._api = api
            if previous is not None:
                previous_http = getattr(previous, "_http", None)
                if previous_http is not None:
                    previous_http.close()
            return api
        except AnonymousGooglePlaySessionError:
            raise
        except Exception as exc:  # noqa: BLE001 - sanitize arbitrary network/client failures
            # Keep only typed status/category fields; never expose response bodies,
            # request URLs, headers, tokens, or arbitrary exception text.
            summary = _safe_exception_summary(exc)
            raise AnonymousGooglePlaySessionError(
                "Could not obtain an anonymous Google Play session from the public "
                f"token dispenser ({summary})."
            ) from None
