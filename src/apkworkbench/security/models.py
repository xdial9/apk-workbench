"""Shared models, exceptions, and certificate helpers for APK signature verification."""
from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class ApkSignatureError(ValueError):
    """Raised when an APK signature structure is malformed or invalid."""


def summarize_certificate(cert: x509.Certificate) -> dict[str, Any]:
    """Return a deterministic, JSON-serializable summary of an X.509 certificate."""
    der = cert.public_bytes(serialization.Encoding.DER)
    pub = cert.public_key()
    key_size = getattr(pub, "key_size", None)
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "version": cert.version.value + 1,
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "public_key_type": type(pub).__name__,
        "key_size": key_size,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "self_issued": cert.subject == cert.issuer,
    }
