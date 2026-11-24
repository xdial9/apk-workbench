"""Cryptographic APK signature verification (v1 JAR/PKCS#7 and v2/v3 APK Signing Block).

Download integrity verification lives in ``apkworkbench.acquisition.verification``
and surface certificate/signing-scheme metadata extraction lives in
``apkworkbench.analysis.surface.identity``. This package performs full
cryptographic verification using ``cryptography``.
"""
from __future__ import annotations

from apkworkbench.security.apk_signature import verify_apk_signature
from apkworkbench.security.models import ApkSignatureError
from apkworkbench.security.pkcs7 import verify_pkcs7_signature
from apkworkbench.security.v1_jar import verify_v1_jar_signature
from apkworkbench.security.v2_v3 import verify_v2_v3_signatures

__all__ = [
    "ApkSignatureError",
    "verify_apk_signature",
    "verify_pkcs7_signature",
    "verify_v1_jar_signature",
    "verify_v2_v3_signatures",
]
