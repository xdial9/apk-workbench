"""Deduction templates (plan v2 S5) — conjunctive facts only, never guesses.

Every deduction carries: the template id, the input fact fingerprints, a
narrative in operator language, a confidence label (L4 law), and
next_steps: directions for the terminal AI handoff (plan.txt PROGRAM
IDENTITY / surface-plan §7A). A deduction without cited fingerprints is
forbidden.
"""
from __future__ import annotations

from typing import Any

from apkworkbench.analysis.surface.facts import FactStore
from apkworkbench.analysis.surface.manifest_v2 import SENSITIVE_PERMISSIONS

DYNAMIC_CODE_LOADING_RULE = "dynamic_code_loading"

# Subset of SENSITIVE_PERMISSIONS checked for DEX API-to-permission mismatch.
# Storage and Bluetooth permissions are excluded because Androguard's bundled
# API-permission mappings lack complete coverage for them and would produce
# false mismatch hints.
PERMISSION_MISMATCH_CANDIDATES: frozenset[str] = SENSITIVE_PERMISSIONS - frozenset({
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BLUETOOTH_CONNECT",
})


def _deduction(
    ded_id: str,
    template: str,
    narrative: str,
    confidence: str,
    fingerprints: list[str],
    next_steps: list[str],
    cites: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": ded_id,
        "template": template,
        "narrative": narrative,
        "confidence": confidence,
        "facts": fingerprints,
        "next_steps": next_steps,
        "cites": cites or [],
    }


def sdk_stack(facts: FactStore, histogram: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    candidates = [
        {"root": root, **data} for root, data in histogram.items()
        if data["owner"] == "third_party_candidate" and data["class_count"] >= 5
    ]
    if not candidates:
        return None
    fingerprints: list[str] = []
    for item in candidates:
        ev = {"path": item["evidence_path"]} if item.get("evidence_path") else None
        fingerprints.append(facts.add("sdk_root", item["root"], evidence=ev, extra={"class_count": item["class_count"]}))
    named = sorted((item["root"] for item in candidates), key=str)
    narrative = (
        # CAP-FREE: was capped at 12 names + "(and more)" - hid SDK roots from AI. List ALL.
        "Third-party SDK roots observed in the bytecode: "
        + ", ".join(named)
        + "."
    )
    return _deduction(
        "D-SDK-HISTOGRAM",
        "sdk_stack",
        narrative,
        "deduced",
        fingerprints,
        [
            (
                "Map each third-party root to a known SDK name via "
                "marker/string evidence; unknown roots are leads (find "
                "their endpoints/keys)."
            ),
            (
                "For identified SDKs, list the data each is known to "
                "collect and cross-check against the endpoint inventory."
            ),
        ],
        # CAP-FREE: was capped at 12 roots, now all roots cited.
        cites=[f"sdk_root:{root}" for root in named],
    )


def packed_or_obfuscated(
    facts: FactStore,
    code_rule_hits: list[str],
    large_asset_blobs: int,
    short_name_ratio: float | None,
    findings: list[dict[str, Any]] | None = None,
    large_asset_blob_paths: list[str] | None = None,
    short_name_smali_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    packed = DYNAMIC_CODE_LOADING_RULE in code_rule_hits and large_asset_blobs > 0
    if packed:
        # D2 fix: cite the findings that actually triggered it (the
        # dynamic-code-loading rule hits) and the large asset blob paths, so
        # the AI can trace it. When a rule hit carries no file:line evidence,
        # pass evidence=None (FactStore records evidence=[]) rather than a
        # synthetic phantom path.
        trigger_evidence = next(
            (
                finding.get("evidence")
                for finding in (findings or [])
                if finding.get("rule_id") == DYNAMIC_CODE_LOADING_RULE
                and isinstance(finding.get("evidence"), dict)
                and finding["evidence"].get("path")
            ),
            None,
        )
        packed_evidence = dict(trigger_evidence) if trigger_evidence else None
        fingerprints = [
            facts.add(
                "packed_indicator",
                "dynamic_code_loading + large asset blob",
                evidence=packed_evidence,
            )
        ]
        cites = []
        for finding in (findings or []):
            if finding.get("rule_id") != DYNAMIC_CODE_LOADING_RULE:
                continue
            ev = finding.get("evidence")
            if isinstance(ev, dict) and ev.get("path"):
                cites.append(
                    f"finding:{finding.get('rule_id')}@{ev.get('path')}:{ev.get('line')}"
                )
        blob_cites = [
            f"apktool/{path}" for path in sorted(large_asset_blob_paths or [])
        ]
        out.append(_deduction(
            "D-PACKED-CANDIDATE",
            "packed_candidate",
            (
                "Dynamic code loading co-occurs with large binary assets: "
                "the app may carry packed/hidden dex loaded at runtime. "
                "Static visibility is limited and confidence of other "
                "findings is reduced accordingly."
            ),
            "hint",
            fingerprints,
            [
                (
                    "Locate the asset blob(s) referenced by the "
                    "DexClassLoader call sites; attempt extraction/decoding; "
                    "record what was recoverable."
                ),
                (
                    "Mark every other conclusion for this app as "
                    "reduced-confidence in the dossier while the packed "
                    "state stands."
                ),
            ],
            cites=cites + blob_cites,
        ))
    if short_name_ratio is not None and short_name_ratio >= 0.6:
        # D3 fix: same treatment — cite the short-name smali files that drove
        # the ratio, not just the number. When no smali paths are provided,
        # pass evidence=None (FactStore records evidence=[]) rather than a
        # synthetic phantom path.
        first_short = next(
            (path for path in sorted(short_name_smali_paths or []) if path),
            None,
        )
        obf_evidence = {"path": f"apktool/{first_short}"} if first_short else None
        fingerprints = [
            facts.add(
                "obfuscation_metric",
                f"short_name_ratio={short_name_ratio:.2f}",
                evidence=obf_evidence,
            )
        ]
        cites = [
            f"apktool/{path}" for path in sorted(short_name_smali_paths or []) if path
        ]
        out.append(_deduction(
            "D-OBFUSCATED-NAMES",
            "obfuscation_level",
            (
                f"Heavy identifier shortening observed (short-name ratio "
                f"{short_name_ratio:.2f}); names are likely "
                "R8/ProGuard-renamed."
            ),
            "deduced",
            fingerprints,
            [
                (
                    "Treat readable-looking class names as tool/library "
                    "remnants; rely on string and API-shape evidence "
                    "instead of names."
                ),
                (
                    "Check for a mapping file accidentally shipped in the "
                    "artifact before concluding names are unrecoverable."
                ),
            ],
            cites=cites,
        ))
    return out


def permission_mismatch(
    requested: list[str],
    used_permissions: set[str],
    facts: FactStore | None = None,
) -> dict[str, Any] | None:
    """Requested sensitive permissions with no DEX-API usage evidence."""
    if facts is None:
        facts = FactStore()
    unused = sorted(
        name for name in requested
        if name in PERMISSION_MISMATCH_CANDIDATES and not any(name in perms for perms in used_permissions)
    )
    if not unused:
        return None
    fingerprints = [
        facts.add("permission_without_static_usage", name) for name in unused
    ]
    narrative = (
        "Requested sensitive permission(s) with no DEX-level API usage "
        "evidence: " + ", ".join(unused) + "."
    )
    return _deduction(
        "D-PERMISSION-MISMATCH",
        "permission_mismatch",
        narrative,
        "hint",
        fingerprints,
        [
            (
                "Trace the permission strings in smali/resources (may be "
                "requested by an SDK manifest merge rather than app code); "
                "identify the owning SDK before claiming the app itself "
                "uses them."
            ),
            (
                "If the requesting component is an SDK, record it as SDK "
                "data collection, not app behavior."
            ),
        ],
        cites=[f"permission:{name}" for name in unused],
    )


def api_surface(
    facts: FactStore,
    endpoints: list[dict[str, Any]],
    routes: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    public_urls = [
        record for record in endpoints
        if record.get("kind") == "url" and record.get("host_class") is None
    ]
    if not public_urls and not routes:
        return None
    fingerprints: list[str] = []
    for record in public_urls:
        value = record.get("canonical") or record["value"]
        extra = {"host": record.get("host"), "host_class": record.get("host_class")}
        if record.get("evidence"):
            for ev in record["evidence"]:
                fingerprints.append(facts.add("api_endpoint", value, evidence=ev, extra=dict(extra)))
        else:
            fingerprints.append(facts.add("api_endpoint", value, evidence=None, extra=dict(extra)))
    fingerprints.extend(
        facts.add("api_route", f"{route_data.get('http_method') or '?'} {route}")
        for route, route_data in sorted(routes.items())
    )
    hosts = sorted(
        {str(record.get("host")) for record in public_urls if record.get("host")}
    )
    narrative = (
        # CAP-FREE: was capped at 10 hosts - hid hosts from AI. List ALL.
        "Static API surface: "
        + (", ".join(hosts) if hosts else "routes without hosts")
        + f"; {len(routes)} route candidates."
    )
    return _deduction(
        "D-API-SURFACE",
        "api_surface_reconstruction",
        narrative,
        "deduced",
        fingerprints,
        [
            (
                "Reconstruct request shapes per route (method + path + "
                "payload models) and attach the endpoints' components as "
                "callers."
            ),
            (
                "Flag any cleartext hosts and any endpoint whose host "
                "matches verified-secrets findings for correlation."
            ),
        ],
        # CAP-FREE: was capped at 12 endpoints, now all endpoints cited.
        cites=[
            f"endpoint:{record.get('canonical') or record['value']}"
            for record in public_urls
        ],
    )