"""Google Play FDFE session adapter with explicit authentication modes.

The Google Play internal API requires a short-lived bearer token. APK Workbench
resolves it through goopdl in one of three modes:

- ``account``: a Google account owned by the operator. goopdl registers a
  device for the account and exchanges an AAS token for the bearer via
  Google's Android setup endpoint. The Aurora dispenser is never contacted.
  Credentials come from, in order: an explicitly provided pair, the
  ``GOOPDL_ACCOUNT_EMAIL``/``GOOPDL_AAS_TOKEN`` environment variables, or the
  account saved by ``goopdl auth login`` (system keyring or goopdl's
  ``account.json``).
- ``anonymous``: the legacy behaviour. A bearer token is obtained anonymously
  from Aurora Store's public token dispenser. For operator and account
  safety this mode fails closed when Google-account environment credentials
  are present: they are not read or used.
- ``auto`` (default): account mode when credentials resolve; anonymous mode
  otherwise. This keeps bulk acquisition working when Aurora's dispenser is
  down, while retaining anonymous access for operators without a configured
  account.

The playstore-cli PlayApi remains responsible for categories, search, charts,
delivery metadata, and downstream downloads in every mode.
"""
from __future__ import annotations

import contextlib
import math
import os
import re
from collections.abc import Callable
from typing import Any

from goopdl import auth as token_auth
from playstore_cli.api import PlayApi
from playstore_cli.device import DEFAULT_PROFILE

AUTH_MODES = ("auto", "account", "anonymous")
_DEFAULT_AUTH_MODE = "auto"
_ACCOUNT_ENV_EMAIL = "GOOPDL_ACCOUNT_EMAIL"
_ACCOUNT_ENV_TOKEN = "GOOPDL_AAS_TOKEN"
_ACCOUNT_ENV_VARS = (_ACCOUNT_ENV_EMAIL, _ACCOUNT_ENV_TOKEN)


class AnonymousGooglePlaySessionError(RuntimeError):
    """Raised when a Play API session cannot be obtained."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class GooglePlayAuthenticationConfigurationError(AnonymousGooglePlaySessionError):
    """Raised when the selected authentication mode cannot be satisfied."""


def validate_auth_mode(mode: Any) -> str:
    value = str(mode or "").strip().lower()
    if value not in AUTH_MODES:
        raise ValueError(
            f"auth_mode must be one of {', '.join(AUTH_MODES)}; got {mode!r}."
        )
    return value


def _is_finite_seconds(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 3600
    )


def _retry_after_of(exc: Exception) -> float | None:
    value = getattr(exc, "retry_after", None)
    return float(value) if _is_finite_seconds(value) else None


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
    if stage in {"auth", "checkin", "toc", "an unexpected stage"}:
        parts.append(f"stage={stage}")
    retry_after = getattr(exc, "retry_after", None)
    if _is_finite_seconds(retry_after):
        parts.append(f"retry_after={retry_after:g}s")
    return "; ".join(parts)


def _mask_email(email: str) -> str:
    """Return a stable, non-identifying rendering of an account email."""
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}" if local else f"***@{domain}"


def _env_account_pair() -> tuple[str, str] | None:
    """(email, aas_token) from the environment; None when neither is set.

    Raises when only part of the pair is configured so a typo can never
    silently fall through to anonymous access.
    """
    email = os.environ.get(_ACCOUNT_ENV_EMAIL, "").strip()
    token = os.environ.get(_ACCOUNT_ENV_TOKEN, "").strip()
    if not email and not token:
        return None
    if not email:
        raise AnonymousGooglePlaySessionError(
            f"{_ACCOUNT_ENV_EMAIL} is required when {_ACCOUNT_ENV_TOKEN} is set."
        )
    if not token:
        raise AnonymousGooglePlaySessionError(
            f"{_ACCOUNT_ENV_TOKEN} is required when {_ACCOUNT_ENV_EMAIL} is set."
        )
    return email, token


def _saved_account(load: Callable[[], tuple[str, str] | None] | None) -> tuple[str, str] | None:
    """(email, aas_token) saved by ``goopdl auth login``, or None."""
    reader: Callable[[], tuple[str, str] | None] | None = load
    if reader is None:
        from goopdl import _account

        reader = _account.load
    saved = reader()
    if saved is None:
        return None
    email, token = saved
    email, token = str(email).strip(), str(token).strip()
    if email and token:
        return email, token
    return None


def _account_scope(credentials: tuple[str, str] | None):
    """Apply goopdl's per-context credentials when account credentials are known.

    Without explicit scope credentials, goopdl consults the
    GOOPDL_ACCOUNT_EMAIL/GOOPDL_AAS_TOKEN environment variables itself.
    """
    if credentials is None:
        return contextlib.nullcontext()
    scope = token_auth._Scope(
        config_dir=None,
        credentials=credentials,
        explicit_credentials=True,
    )
    return token_auth._use_scope(scope)


def describe_auth_mode(
    mode: str,
    *,
    load_saved_account: Callable[[], tuple[str, str] | None] | None = None,
    read_env: Callable[[], tuple[str, str] | None] | None = None,
) -> dict[str, Any]:
    """Summarize how an authentication mode currently resolves (for ``doctor``)."""
    validate_auth_mode(mode)
    report: dict[str, Any] = {
        "configured_mode": validate_auth_mode(mode),
        "resolved_mode": None,
        "account_source": None,
        "account_email": None,
    }
    try:
        environment = (read_env or _env_account_pair)()
    except AnonymousGooglePlaySessionError:
        report["account_source"] = "environment-incomplete"
        return report
    if environment is not None:
        report.update(
            resolved_mode="account",
            account_source="environment",
            account_email=_mask_email(environment[0]),
        )
        return report
    if mode == "anonymous":
        report.update(resolved_mode="anonymous")
        return report
    try:
        saved = _saved_account(load_saved_account)
    except Exception:  # noqa: BLE001 - saved-storage problems must not crash a report
        report.update(
            resolved_mode=None,
            account_source="saved-account-unreadable",
            account_email="***",
        )
        return report
    if saved is not None:
        report.update(
            resolved_mode="account",
            account_source="goopdl_saved_account",
            account_email=_mask_email(saved[0]),
        )
        return report
    report.update(
        resolved_mode="anonymous" if mode != "account" else None,
        account_source=None if mode != "account" else "none-configured",
    )
    return report


class _ProfileView:
    """Expose the profile methods PlayApi needs, using the session-issued device."""

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


class GooglePlaySession:
    """Create PlayApi instances backed by goopdl device sessions.

    The mode controls where the short-lived bearer token originates: the
    operator's own Google account (stable) or Aurora's public token dispenser
    (anonymous). PlayApi consumption is identical in both cases; goopdl owns
    the token/device caches, rotates rejected tokens, and retires a device
    registration only after a second consecutive Play rejection.
    """

    def __init__(
        self,
        *,
        auth_mode: str = _DEFAULT_AUTH_MODE,
        arch: str = "arm64",
        country: str | None = None,
        profile: str | None = None,
        dispenser_url: str | None = None,
        credentials: tuple[str, str] | None = None,
        load_saved_account: Callable[[], tuple[str, str] | None] | None = None,
    ) -> None:
        if country is not None:
            country = country.strip().upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                raise ValueError("country must be a two-letter ISO country code")
        self.auth_mode = validate_auth_mode(auth_mode)
        self.arch = arch
        self.country = country
        self.profile = profile
        self.dispenser_url = dispenser_url
        self._explicit_credentials = credentials
        self._load_saved_account = load_saved_account
        self._credentials: tuple[str, str] | None = None
        self.retry_after: float | None = None
        self._auth: dict[str, Any] | None = None
        self._api: PlayApi | None = None

    # -- credential resolution -------------------------------------------------
    def _require_anonymous_environment(self) -> None:
        # Anonymous mode fails closed rather than silently using a user's
        # saved Google account when goopdl's optional account-mode
        # environment is present.
        configured = [name for name in _ACCOUNT_ENV_VARS if os.environ.get(name, "").strip()]
        if configured:
            raise AnonymousGooglePlaySessionError(
                "APK Workbench is configured for anonymous Play access only "
                "(auth_mode='anonymous'). Unset GOOPDL_ACCOUNT_EMAIL and "
                "GOOPDL_AAS_TOKEN, or set auth_mode='account' or 'auto' to "
                "use a Google account."
            )

    def _resolve_credentials(self) -> tuple[str, str] | None:
        """Resolve account credentials, or None when none are configured."""
        if self._explicit_credentials is not None:
            email, token = self._explicit_credentials
            email, token = str(email).strip(), str(token).strip()
            return (email, token) if email and token else None
        environment = _env_account_pair()
        if environment is not None:
            return environment
        return _saved_account(self._load_saved_account)

    # -- token acquisition -----------------------------------------------------
    def _token_options(self) -> dict[str, Any]:
        options: dict[str, Any] = {
            "arch": self.arch,
            "raise_on_error": True,
        }
        if self.country:
            options["country"] = self.country
        if self.profile:
            options["profile"] = self.profile
        if self.dispenser_url:
            options["dispenser_url"] = self.dispenser_url
        return options

    def _account_scope(self):
        return _account_scope(self._credentials)

    def _get_auth(self, *, force_refresh: bool) -> dict[str, Any]:
        self.retry_after = None
        options = self._token_options()
        with self._account_scope():
            if force_refresh and self._auth is not None:
                auth_data = token_auth.replace_pool_token(self._auth, **options)
            else:
                auth_data = token_auth.pick_pool_token(**options)
        if not isinstance(auth_data, dict):
            session_label = (
                "account" if self._credentials is not None else "dispenser"
            )
            raise AnonymousGooglePlaySessionError(
                f"The {session_label} token source did not return a usable "
                "Play device session."
            )
        if not auth_data.get("authToken") or not auth_data.get("gsfId"):
            raise AnonymousGooglePlaySessionError(
                "The Play session response is missing required device credentials."
            )
        return auth_data

    def new_api(self, *, force_refresh: bool = False) -> PlayApi:
        """Return a PlayApi, refreshing the device session after a 401."""
        if self.auth_mode == "anonymous":
            self._require_anonymous_environment()
        try:
            credentials = self._resolve_credentials()
        except AnonymousGooglePlaySessionError:
            if self.auth_mode == "account":
                partial = AnonymousGooglePlaySessionError(
                    f"Account credentials are incomplete: {_env_account_pair.__name__} "
                    "requires both variables; see auth_mode documentation."
                )
                raise partial from None
            credentials = None  # auto mode cannot use a partial pair; stay anonymous
        if self.auth_mode == "account" and credentials is None:
            raise GooglePlayAuthenticationConfigurationError(
                "auth_mode='account' requires Google account credentials. "
                "Run `goopdl auth login` (saves the account), export "
                "GOOPDL_ACCOUNT_EMAIL and GOOPDL_AAS_TOKEN, or switch to "
                "auth_mode='auto' to fall back to the public dispenser."
            )
        with_account = self.auth_mode != "anonymous" and credentials is not None
        self._credentials = credentials if with_account else None
        source_label = "Google account" if with_account else "public token dispenser"
        try:
            auth_data = self._get_auth(force_refresh=force_refresh)
        except AnonymousGooglePlaySessionError:
            raise
        except Exception as exc:  # noqa: BLE001 - sanitize arbitrary network/client failures
            # Keep only typed status/category fields; never expose request
            # bodies, URLs, headers, tokens, or arbitrary exception text.
            error = AnonymousGooglePlaySessionError(
                f"Could not obtain a Google Play session via the {source_label} "
                f"({_safe_exception_summary(exc)}).",
                retry_after=_retry_after_of(exc),
            )
            raise error from None
        device = {
            # PlayApi loads this profile during construction. Its UA and
            # operator fields are immediately replaced by the matching
            # session-issued device information below.
            "profile": DEFAULT_PROFILE,
            "gsfId": str(auth_data["gsfId"]),
            # goopdl uses "deviceCheckInConsistencyToken"; playstore-cli
            # indexes the compatibility key with a lowercase "in".
            "deviceCheckinConsistencyToken": str(
                auth_data.get("deviceCheckInConsistencyToken") or ""
            ),
            "locale": f"en_{self.country or 'US'}",
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


AnonymousGooglePlaySession = GooglePlaySession
"""Backwards-compatible alias for callers that constructed the dispenser session."""
