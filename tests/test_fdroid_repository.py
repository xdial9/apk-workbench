"""Tests for bounded F-Droid index retrieval and signature verification."""
from __future__ import annotations

from collections.abc import Iterable

import pytest

from apkworkbench.sources.fdroid_repository import (
    FdroidRepositoryClient,
    FdroidRepositoryError,
)


FINGERPRINT = "37D2C98789D8311948394E3E41E7044E1DBA2E89"
KEY_URL = (
    "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x"
    + FINGERPRINT
)


class FakeVerifier:
    def __init__(self, *, trusted: set[str] | None = None, valid: bool = True):
        self.trusted_fingerprints = {FINGERPRINT} if trusted is None else trusted
        self.valid = valid
        self.imported = None
        self.verified_payload = None

    def import_public_key(self, key_data: bytes, expected_fingerprint: str):
        assert key_data == b"armored public key"
        self.imported = expected_fingerprint
        return expected_fingerprint

    def verify_detached_signature(self, data_path, sig_path, fingerprint):
        from pathlib import Path

        assert fingerprint == FINGERPRINT
        self.verified_payload = (
            Path(data_path).read_bytes(),
            Path(sig_path).read_bytes(),
        )
        return self.valid


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: Iterable[bytes] | None = None,
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = list(chunks) if chunks is not None else [body]
        self.closed = False

    def iter_content(self, chunk_size: int):
        assert chunk_size > 0
        yield from self._chunks

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        return response


def make_client(session, verifier=None, **overrides):
    return FdroidRepositoryClient(
        verifier or FakeVerifier(),
        repository_url="https://f-droid.org/repo",
        key_url=KEY_URL,
        signer_fingerprint=FINGERPRINT,
        session=session,
        **overrides,
    )


def good_session():
    return FakeSession(
        [
            FakeResponse(b"armored public key"),
            FakeResponse(b'{"packages": {}}'),
            FakeResponse(b"-----BEGIN PGP SIGNATURE-----"),
        ]
    )


def test_verified_index_is_returned_only_after_pinned_signature_check():
    session = good_session()
    verifier = FakeVerifier()
    client = make_client(session, verifier)

    result = client.fetch_verified_index()

    assert result == b'{"packages": {}}'
    assert verifier.imported == FINGERPRINT
    assert verifier.verified_payload == (
        b'{"packages": {}}',
        b"-----BEGIN PGP SIGNATURE-----",
    )
    assert [call[0] for call in session.calls] == [
        KEY_URL,
        "https://f-droid.org/repo/index-v2.json",
        "https://f-droid.org/repo/index-v2.json.asc",
    ]
    assert all(call[1]["allow_redirects"] is False for call in session.calls)
    assert all(call[1]["stream"] is True for call in session.calls)


def test_invalid_signature_fails_closed():
    client = make_client(good_session(), FakeVerifier(valid=False))

    with pytest.raises(FdroidRepositoryError, match="signature is invalid"):
        client.fetch_verified_index()


def test_signer_must_be_in_configured_allowlist_before_network_access():
    session = good_session()
    client = make_client(session, FakeVerifier(trusted=set()))

    with pytest.raises(FdroidRepositoryError, match="trust allowlist"):
        client.fetch_verified_index()

    assert session.calls == []


def test_declared_oversize_response_is_rejected():
    session = FakeSession(
        [FakeResponse(b"", headers={"Content-Length": "11"})]
    )
    client = make_client(session, max_key_bytes=10)

    with pytest.raises(FdroidRepositoryError, match="exceeds"):
        client.fetch_verified_index()


def test_streamed_oversize_response_is_rejected_without_content_length():
    session = FakeSession(
        [FakeResponse(b"", chunks=[b"123456", b"789012"])]
    )
    client = make_client(session, max_key_bytes=10)

    with pytest.raises(FdroidRepositoryError, match="exceeds"):
        client.fetch_verified_index()


def test_redirect_is_rejected():
    session = FakeSession([FakeResponse(b"", status_code=302)])
    client = make_client(session)

    with pytest.raises(FdroidRepositoryError, match="Refusing redirect"):
        client.fetch_verified_index()


def test_non_https_repository_url_is_rejected():
    with pytest.raises(FdroidRepositoryError, match="HTTPS"):
        FdroidRepositoryClient(
            FakeVerifier(),
            repository_url="http://f-droid.org/repo",
            key_url=KEY_URL,
            signer_fingerprint=FINGERPRINT,
            session=good_session(),
        )


def test_invalid_content_length_is_rejected():
    session = FakeSession(
        [FakeResponse(b"", headers={"Content-Length": "unknown"})]
    )
    client = make_client(session)

    with pytest.raises(FdroidRepositoryError, match="Invalid Content-Length"):
        client.fetch_verified_index()



def test_fresh_verified_cache_is_reused_and_signature_is_rechecked(tmp_path):
    first_session = good_session()
    first_client = make_client(first_session)
    first = first_client.fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
    )

    assert first == b'{"packages": {}}'
    assert len(first_session.calls) == 3
    cache_files = list((tmp_path / "cache").glob("*.index-v2.json*"))
    assert len(cache_files) == 2
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in cache_files)
    assert (tmp_path / "cache").stat().st_mode & 0o777 == 0o700

    second_session = FakeSession([])
    second_verifier = FakeVerifier()
    second_client = make_client(second_session, second_verifier)
    second = second_client.fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
    )

    assert second == first
    assert second_session.calls == []
    assert second_verifier.verified_payload == (
        b'{"packages": {}}',
        b"-----BEGIN PGP SIGNATURE-----",
    )


def test_expired_cache_is_refreshed_from_the_repository(tmp_path):
    import os
    import time

    make_client(good_session()).fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
    )

    old_time = time.time() - 7200
    for path in (tmp_path / "cache").glob("*.index-v2.json*"):
        os.utime(path, (old_time, old_time))

    fresh_session = good_session()
    result = make_client(fresh_session).fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=60,
    )

    assert result == b'{"packages": {}}'
    assert len(fresh_session.calls) == 3


def test_force_refresh_bypasses_a_valid_cache(tmp_path):
    make_client(good_session()).fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
    )

    session = good_session()
    result = make_client(session).fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
        force_refresh=True,
    )

    assert result == b'{"packages": {}}'
    assert len(session.calls) == 3


def test_invalid_cached_signature_is_never_used_and_network_refresh_must_verify(tmp_path):
    make_client(good_session()).fetch_verified_index(
        cache_dir=tmp_path / "cache",
        cache_ttl_seconds=3600,
    )

    session = good_session()
    client = make_client(session, FakeVerifier(valid=False))

    with pytest.raises(FdroidRepositoryError, match="signature is invalid"):
        client.fetch_verified_index(
            cache_dir=tmp_path / "cache",
            cache_ttl_seconds=3600,
        )

    assert len(session.calls) == 3
