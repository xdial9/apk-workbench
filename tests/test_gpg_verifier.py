"""Tests for isolated GPG signature verification."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from apkworkbench.core.config import Config
from apkworkbench.security.gpg_verifier import GpgVerificationError, GpgVerifier


@pytest.fixture
def signed_fixture(tmp_path: Path):
    if not shutil.which("gpg"):
        pytest.skip("GnuPG is not installed")
    signer_home = tmp_path / "signer"
    verifier_home = tmp_path / "verifier"
    signer_home.mkdir(mode=0o700)
    verifier_home.mkdir(mode=0o700)

    params = tmp_path / "keyparams"
    params.write_text(
        "%no-protection\n"
        "Key-Type: RSA\nKey-Length: 2048\n"
        "Name-Real: APK Workbench Test\n"
        "Name-Email: test@example.invalid\n"
        "Expire-Date: 0\n%commit\n",
        encoding="utf-8",
    )
    generated = subprocess.run(
        ["gpg", "--homedir", str(signer_home), "--batch", "--generate-key", str(params)],
        capture_output=True, text=True, timeout=60,
    )
    if generated.returncode:
        pytest.skip(f"GnuPG test key generation unavailable: {generated.stderr}")

    listing = subprocess.run(
        ["gpg", "--homedir", str(signer_home), "--batch", "--with-colons",
         "--fingerprint", "--list-keys"],
        capture_output=True, text=True, check=True,
    )
    fingerprint = next(
        line.split(":")[9] for line in listing.stdout.splitlines()
        if line.startswith("fpr:")
    )
    pubkey = subprocess.run(
        ["gpg", "--homedir", str(signer_home), "--batch", "--armor", "--export", fingerprint],
        capture_output=True, check=True,
    ).stdout

    data = tmp_path / "payload.bin"
    data.write_bytes(b"APK Workbench signature test payload")
    signature = tmp_path / "payload.bin.asc"
    subprocess.run(
        ["gpg", "--homedir", str(signer_home), "--batch", "--armor",
         "--detach-sign", "--output", str(signature), str(data)],
        capture_output=True, check=True,
    )
    altered = tmp_path / "altered.bin"
    altered.write_bytes(b"altered payload")

    config = Config(config_file=tmp_path / "nonexistent.yaml", environ={"HOME": str(tmp_path)})
    config._data["gpg"]["homedir"] = str(verifier_home)
    config._data["gpg"]["trusted_fingerprints"] = [fingerprint]
    verifier = GpgVerifier(config)
    imported = verifier.import_public_key(pubkey, expected_fingerprint=fingerprint)
    assert imported == fingerprint
    return verifier, fingerprint, data, signature, altered


def test_valid_signature_from_pinned_primary_key_is_accepted(signed_fixture):
    verifier, fingerprint, data, signature, _ = signed_fixture
    assert verifier.verify_detached_signature(data, signature, fingerprint) is True


def test_modified_data_is_rejected(signed_fixture):
    verifier, fingerprint, _, signature, altered = signed_fixture
    assert verifier.verify_detached_signature(altered, signature, fingerprint) is False


def test_unconfigured_fingerprint_is_rejected(signed_fixture):
    verifier, _, data, signature, _ = signed_fixture
    with pytest.raises(GpgVerificationError, match="allowlist"):
        verifier.verify_detached_signature(data, signature, "A" * 40)


def test_missing_input_is_an_error(signed_fixture, tmp_path):
    verifier, fingerprint, _, signature, _ = signed_fixture
    with pytest.raises(GpgVerificationError, match="does not exist"):
        verifier.verify_detached_signature(tmp_path / "missing", signature, fingerprint)


def test_signature_from_non_pinned_key_is_rejected(signed_fixture):
    verifier, _, data, signature, _ = signed_fixture
    non_signer_fingerprint = "A" * 40
    verifier.trusted_fingerprints = {non_signer_fingerprint}
    assert verifier.verify_detached_signature(
        data, signature, non_signer_fingerprint
    ) is False


def test_empty_trust_allowlist_fails_closed(signed_fixture):
    verifier, fingerprint, data, signature, _ = signed_fixture
    verifier.trusted_fingerprints = set()
    with pytest.raises(GpgVerificationError, match="No trusted"):
        verifier.verify_detached_signature(data, signature, fingerprint)
