"""Unified cryptographic APK signature verifier (v1 JAR + v2/v3 APK Signing Block)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from apkworkbench.security.v1_jar import verify_v1_jar_signature
from apkworkbench.security.v2_v3 import verify_v2_v3_signatures


def verify_apk_signature(apk_path: str | Path) -> dict[str, Any]:
    """Cryptographically verify APK Signature Scheme v1, v2, and v3 on ``apk_path``.

    Returns a JSON-serializable report containing:
    - ``status``: ``"verified"``, ``"unsigned"``, or ``"failed"``
    - ``verified``: boolean indicating cryptographic verification passed with no errors
    - ``schemes_present`` / ``schemes_verified``: lists of scheme names
    - ``certificates``: deduplicated verified signing certificate summaries
    - ``schemes``: per-scheme detailed verification output (``v1``, ``v2``, ``v3``)
    - ``errors`` / ``diagnostics``: any failure reasons or downgrade warnings
    """
    path = Path(apk_path)
    report: dict[str, Any] = {
        "status": "failed",
        "verified": False,
        "path": str(path),
        "size_bytes": 0,
        "schemes_present": [],
        "schemes_verified": [],
        "certificates": [],
        "schemes": {},
        "errors": [],
        "diagnostics": [],
    }
    if not path.is_file():
        report["errors"].append(f"APK file does not exist or is not a regular file: {path}")
        return report

    report["size_bytes"] = path.stat().st_size

    v1_res = verify_v1_jar_signature(path)
    v2_v3_res = verify_v2_v3_signatures(path)
    v2_res = v2_v3_res["v2"]
    v3_res = v2_v3_res["v3"]

    report["schemes"] = {
        "v1": v1_res,
        "v2": v2_res,
        "v3": v3_res,
    }

    errors: list[str] = []
    if v2_v3_res["signing_block_error"]:
        errors.append(f"signing_block: {v2_v3_res['signing_block_error']}")

    schemes_present: list[str] = []
    schemes_verified: list[str] = []
    seen_certs: dict[str, dict[str, Any]] = {}

    for scheme_name, s_res in (("v1", v1_res), ("v2", v2_res), ("v3", v3_res)):
        if s_res["present"]:
            schemes_present.append(scheme_name)
        if s_res["verified"]:
            schemes_verified.append(scheme_name)
            for cert in s_res["certificates"]:
                entry = seen_certs.get(cert["sha256"])
                if entry is None:
                    entry = {**cert, "schemes": [scheme_name]}
                    seen_certs[cert["sha256"]] = entry
                elif scheme_name not in entry["schemes"]:
                    entry["schemes"].append(scheme_name)
        for err in s_res["errors"]:
            errors.append(f"{scheme_name}: {err}")

    # Enforce Android X-Android-APK-Signed downgrade protection when v1 claims v2/v3,
    # and v2 0xbeeff00d stripping protection when v2 declares v3.
    claimed_schemes = set(v1_res.get("x_android_apk_signed") or [])
    if v1_res["present"]:
        if 2 in claimed_schemes and not v2_res["present"]:
            errors.append(
                "downgrade: v1 X-Android-APK-Signed declares scheme 2, but v2 block is absent"
            )
        if 3 in claimed_schemes and not v3_res["present"]:
            errors.append(
                "downgrade: v1 X-Android-APK-Signed declares scheme 3, but v3 block is absent"
            )
    v2_stripping = set(v2_res.get("stripping_protection_versions") or [])
    if v2_res["present"] and 3 in v2_stripping and not v3_res["present"]:
        errors.append(
            "downgrade: v2 stripping protection (0xbeeff00d) declares scheme 3, but v3 block is absent"
        )

    if v2_v3_res.get("v31_present"):
        report["diagnostics"].append({
            "code": "apk_v31_block_present",
            "message": "APK Signing Block v3.1 (0x1b93ad61) is present; v3.1 rotation verification is not separately evaluated.",
        })

    report["schemes_present"] = schemes_present
    report["schemes_verified"] = schemes_verified
    report["certificates"] = list(seen_certs.values())
    report["errors"] = errors

    if errors:
        report["status"] = "failed"
        report["verified"] = False
    elif not schemes_present:
        report["status"] = "unsigned"
        report["verified"] = False
    elif set(schemes_present) == set(schemes_verified):
        report["status"] = "verified"
        report["verified"] = True
    else:
        report["status"] = "failed"
        report["verified"] = False

    return report
