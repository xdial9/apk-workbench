"""Detached OpenPGP signature verification with explicit primary-key pinning."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from ..core.config import Config


class GpgVerificationError(Exception):
    """Raised when GnuPG cannot perform a verification operation."""


_FINGERPRINT_RE = re.compile(r"^[A-Fa-f0-9]{40,64}$")


class GpgVerifier:
    """Use a dedicated GnuPG home and require the pinned primary fingerprint."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.gpg = str(self.config.get("gpg.executable", self.config.get("tools.gpg", "gpg")))
        self.gpg_homedir = Path(self.config.get("gpg.homedir")).expanduser()
        self.timeout = int(self.config.get("gpg.timeout_seconds", 30))
        self.trusted_fingerprints = {
            str(fp).replace(" ", "").upper()
            for fp in self.config.get("gpg.trusted_fingerprints", [])
        }

    def _home(self) -> str:
        self.gpg_homedir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.gpg_homedir, 0o700)
        except OSError as exc:
            raise GpgVerificationError(f"Cannot secure GPG home {self.gpg_homedir}: {exc}") from exc
        return str(self.gpg_homedir)

    def _run(self, args: list[str], *, input_data: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self.gpg, "--homedir", self._home(), "--batch", "--no-tty", *args],
                input=input_data,
                capture_output=True,
                text=input_data is None,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GpgVerificationError("GPG operation timed out.") from exc
        except FileNotFoundError as exc:
            raise GpgVerificationError(f"GPG executable not found: {self.gpg}") from exc
        except OSError as exc:
            raise GpgVerificationError(f"Unable to execute GPG: {exc}") from exc

    def import_public_key(self, key_data: bytes, expected_fingerprint: str | None = None) -> str:
        """Import key material and return its primary fingerprint."""
        result = self._run(["--import"], input_data=key_data)
        if result.returncode != 0:
            raise GpgVerificationError(f"GPG key import failed: {result.stderr.strip()}")
        listing = self._run(["--with-colons", "--fingerprint", "--list-keys"])
        if listing.returncode != 0:
            raise GpgVerificationError(f"Cannot list imported GPG keys: {listing.stderr.strip()}")

        fingerprints: list[str] = []
        awaiting_primary = False
        for line in listing.stdout.splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                awaiting_primary = True
            elif fields[0] == "fpr" and awaiting_primary and len(fields) > 9:
                fingerprints.append(fields[9].upper())
                awaiting_primary = False

        if expected_fingerprint:
            expected = self._normalize_fingerprint(expected_fingerprint)
            if expected not in fingerprints:
                raise GpgVerificationError("Imported key does not contain the expected primary fingerprint.")
            return expected
        if len(fingerprints) != 1:
            raise GpgVerificationError(
                f"Expected exactly one primary key in the GPG home; found {len(fingerprints)}."
            )
        return fingerprints[0]

    @staticmethod
    def _normalize_fingerprint(fingerprint: str) -> str:
        normalized = re.sub(r"\s+", "", fingerprint).upper()
        if not _FINGERPRINT_RE.fullmatch(normalized):
            raise GpgVerificationError("A full hexadecimal OpenPGP fingerprint is required.")
        return normalized

    def verify_detached_signature(
        self, data_path: str | Path, sig_path: str | Path, trusted_fingerprint: str
    ) -> bool:
        """Return True only for a cryptographically valid signature by the pinned primary key."""
        expected = self._normalize_fingerprint(trusted_fingerprint)
        if not self.trusted_fingerprints:
            raise GpgVerificationError(
                "No trusted OpenPGP fingerprints are configured; refusing verification."
            )
        if expected not in self.trusted_fingerprints:
            raise GpgVerificationError("Requested fingerprint is not in the configured trust allowlist.")

        data = Path(data_path)
        signature = Path(sig_path)
        if not data.is_file() or not signature.is_file():
            raise GpgVerificationError("Signed data file or detached signature file does not exist.")

        result = self._run(
            ["--status-fd", "1", "--verify", str(signature), str(data)]
        )
        status_lines = result.stdout.splitlines()
        valid_fingerprints: list[str] = []
        bad_signature = False
        for line in status_lines:
            if not line.startswith("[GNUPG:] "):
                continue
            fields = line[len("[GNUPG:] "):].split()
            if not fields:
                continue
            if fields[0] == "VALIDSIG" and len(fields) >= 2:
                signing_fp = fields[1].upper()
                primary_fp = fields[10].upper() if len(fields) >= 11 else signing_fp
                valid_fingerprints.append(primary_fp)
            elif fields[0] in {"BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"}:
                bad_signature = True

        if result.returncode != 0 or bad_signature or not valid_fingerprints:
            return False
        return any(fp == expected for fp in valid_fingerprints)
