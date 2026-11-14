"""Manifest v2 parser (plan v2 S3): full element/attr fact map + deductions.

Coverage added over the 0.2.0 parser (surface.txt 1A list):
- intent-filter DATA tuples (scheme/host/port/mimeType/path patterns) — the
  deep-link surface — plus derived deep-link findings;
- <meta-data> keys AND values (credential delivery channel);
- <provider> authorities/grantUriPermissions/read+write permissions;
- <queries> package-visibility declarations;
- custom <permission>/<permission-group>/<permission-tree> definitions;
- backup posture: allowBackup default-true deduction + dataExtractionRules /
  fullBackupContent file resolution facts (parser wired by the driver);
- free anomaly deductions from data already captured (versionCode shape,
  minSdk > targetSdk).
Compat: every established fact key and finding rule_id is preserved
(appdev.txt §15 contract); new keys are additive only.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.findings import build_finding

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
PERMISSION_TAGS = {
    "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m",
}
KEY_LIKE_NAME_MARKERS = (
    "api_key", "apikey", "api-key", "key", "token", "secret", "dsn",
    "application_id", "app_id", "client_id",
)


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def android_attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(ANDROID_NS + name) or element.attrib.get(name)


def stripped_attrs(element: ET.Element) -> dict[str, Any]:
    """All attributes with the android: namespace prefix removed."""
    return {
        key.rsplit("}", 1)[-1]: value
        for key, value in element.attrib.items()
    }


def element_tostring(element: ET.Element) -> str:
    return ET.tostring(element, encoding="unicode")


def parse_intent_filter(child: ET.Element) -> dict[str, Any]:
    actions = [android_attr(node, "name") for node in child if local(node.tag) == "action"]
    categories = [android_attr(node, "name") for node in child if local(node.tag) == "category"]
    data = [
        stripped_attrs(node) for node in child if local(node.tag) == "data"
    ]
    return {
        "actions": [action for action in actions if action],
        "categories": [category for category in categories if category],
        "data": data,
    }


def deep_link_targets(filters: list[dict[str, Any]]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for entry in filters:
        for data in entry["data"]:
            scheme = data.get("scheme")
            if not scheme:
                continue
            targets.append({
                "scheme": scheme,
                "host": data.get("host", ""),
                "port": data.get("port", ""),
                "path": data.get("path", "")
                or data.get("pathPrefix", "")
                or data.get("pathPattern", ""),
                "mime_type": data.get("mimeType", ""),
            })
    return targets


def parse_meta_data(component: ET.Element) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for node in component.iter():
        if local(node.tag) != "meta-data":
            continue
        name = android_attr(node, "name")
        if not name:
            continue
        entries.append({
            "name": name,
            "value": android_attr(node, "value"),
            "resource": android_attr(node, "resource"),
        })
    return entries


def looks_like_key(name: str, value: str | None) -> bool:
    lowered = name.lower()
    if not value:
        return False
    if any(marker in lowered for marker in KEY_LIKE_NAME_MARKERS):
        return True
    return value.startswith(("AIza", "ca-app-pub-"))


def parse_provider(component: ET.Element) -> dict[str, Any]:
    return {
        "authorities": [
            item for item in (android_attr(component, "authorities") or "").split(";") if item
        ],
        "grant_uri_permissions": android_attr(component, "grantUriPermissions"),
        "read_permission": android_attr(component, "readPermission"),
        "write_permission": android_attr(component, "writePermission"),
        "exported": android_attr(component, "exported"),
    }


def parse_queries(root: ET.Element) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for node in root:
        if local(node.tag) != "queries":
            continue
        for child in node:
            child_tag = local(child.tag)
            if child_tag == "package":
                entries.append({
                    "kind": "package", "name": android_attr(child, "name"),
                })
            elif child_tag == "provider":
                entries.append({
                    "kind": "provider",
                    "authorities": android_attr(child, "authorities"),
                })
            elif child_tag == "intent":
                entries.append({
                    "kind": "intent", "filter": parse_intent_filter(child),
                })
    return entries


def parse_network_security_config(path: Path, relative: str) -> dict[str, Any]:
    """NSC v2: base-config + domain-config cleartext, trust anchors, pins."""
    facts: dict[str, Any] = {
        "reference": relative,
        "status": "parsed",
        "base_config": None,
        "domains": [],
        "trust_anchors": [],
        "pins": [],
    }
    findings: list[dict[str, Any]] = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}",
                "facts": facts, "findings": findings}
    for node in root.iter():
        tag = local(node.tag)
        if tag == "base-config":
            cleartext = android_attr(node, "cleartextTrafficPermitted")
            facts["base_config"] = {"cleartext_traffic_permitted": cleartext}
            if cleartext == "true":
                findings.append(build_finding(
                    "network_config_cleartext", "network_security", "high",
                    "Network security config permits cleartext traffic",
                    "A base-config explicitly permits cleartext traffic.",
                    relative, None, element_tostring(node), 0.99,
                ))
        elif tag == "domain-config":
            domains = [
                (child.text or "").strip() for child in node
                if local(child.tag) == "domain"
            ]
            cleartext = android_attr(node, "cleartextTrafficPermitted")
            facts["domains"].append({
                "domains": domains,
                "cleartext_traffic_permitted": cleartext,
            })
            if cleartext == "true":
                findings.append(build_finding(
                    "network_config_domain_cleartext", "network_security", "high",
                    "Per-domain cleartext permitted: " + ", ".join(domains),
                    "A domain-config explicitly permits cleartext for these domains.",
                    relative, None, element_tostring(node), 0.95,
                ))
        elif tag == "trust-anchors":
            anchors = [
                stripped_attrs(cert) for child in node
                if local(child.tag) == "certificates"
                for cert in [child]
            ]
            facts["trust_anchors"].extend(anchors)
            for anchor in anchors:
                if anchor.get("src") == "user":
                    findings.append(build_finding(
                        "network_config_user_trust_anchor", "network_security", "high",
                        "Network security config trusts user-added certificates",
                        "Trusting user anchors enables installed-certificate MITM.",
                        relative, None, element_tostring(node), 0.93,
                    ))
        elif tag == "pin-set":
            for pin in node.iter():
                if local(pin.tag) == "pin":
                    facts["pins"].append({
                        "digest": pin.attrib.get("digest"),
                        "value": (pin.text or "").strip(),
                    })
    return {"status": "parsed", "facts": facts, "findings": findings}


def parse_backup_rules(path: Path, relative: str) -> dict[str, Any]:
    """dataExtractionRules / fullBackupContent XML: entries as facts."""
    facts: dict[str, Any] = {
        "reference": relative,
        "status": "parsed",
        "entries": [],
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        facts["status"] = "failed"
        facts["error"] = f"{type(exc).__name__}: {exc}"
        return facts
    for node in root.iter():
        tag = local(node.tag)
        if tag in {"include", "exclude"}:
            facts["entries"].append({
                "action": tag,
                "domain": android_attr(node, "domain"),
                "path": android_attr(node, "path"),
            })
        elif tag in {"cloud-backup", "device-transfer", "d2d-backup"}:
            facts["entries"].append({"action": tag})
    return facts


def parse_manifest_v2(
    path: Path,
    relative: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Full-fidelity manifest parse; established keys preserved, new ones additive."""
    facts: dict[str, Any] = {
        "package": None, "version_code": None, "version_name": None,
        "min_sdk": None, "target_sdk": None,
        "permissions": [],
        "application": {}, "components": [],
        # v2 additions (additive):
        "deep_links": [], "meta_data": [], "providers": [],
        "queries": [], "permission_definitions": [], "uses_feature": [],
        "intent_filters": [], "instrumentation": None,
        "shared_user_id": None, "backup": {"allow_backup": None},
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", **facts}

    facts["package"] = root.attrib.get("package")
    raw_version_code = android_attr(root, "versionCode")
    facts["version_code"] = raw_version_code
    facts["version_name"] = android_attr(root, "versionName")
    facts["shared_user_id"] = android_attr(root, "sharedUserId")

    if raw_version_code is not None and not str(raw_version_code).isdigit():
        findings.append(build_finding(
            "manifest_version_code_anomaly", "manifest", "medium",
            "versionCode is not a plain integer",
            f"versionCode {raw_version_code!r} may break upgrade ordering; verify build config.",
            relative, None, element_tostring(root), 0.9,
        ))

    for element in root:
        tag = local(element.tag)
        if tag == "uses-sdk":
            facts["min_sdk"] = android_attr(element, "minSdkVersion")
            facts["target_sdk"] = android_attr(element, "targetSdkVersion")
        elif tag in PERMISSION_TAGS:
            name = android_attr(element, "name")
            if not name:
                continue
            facts["permissions"].append(name)
            if name.startswith("android.permission."):
                severity = "info"
            else:
                severity = "info"
            findings.append(build_finding(
                "sensitive_permission" if name in SENSITIVE_PERMISSIONS else "permission_requested",
                "permissions", severity,
                f"Permission requested: {name}",
                "Permission request is an exposure indicator, not proof that the permission is used.",
                relative, None, element_tostring(element), 0.99,
            ))
        elif tag in {"permission", "permission-group", "permission-tree"}:
            facts["permission_definitions"].append({
                "kind": tag, **stripped_attrs(element),
            })
        elif tag == "uses-feature":
            facts["uses_feature"].append(stripped_attrs(element))
        elif tag == "instrumentation":
            facts["instrumentation"] = stripped_attrs(element)
        elif tag == "queries":
            facts["queries"] = parse_queries_from_node(element)
        elif tag == "application":
            parse_application(element, relative, findings, facts)

    if (
        facts["min_sdk"] is not None and facts["target_sdk"] is not None
        and str(facts["min_sdk"]).isdigit() and str(facts["target_sdk"]).isdigit()
        and int(facts["min_sdk"]) > int(facts["target_sdk"])
    ):
        findings.append(build_finding(
            "manifest_sdk_anomaly", "manifest", "medium",
            "minSdkVersion exceeds targetSdkVersion",
            "Install floor above target level is inconsistent; review build config.",
            relative, None, element_tostring(root), 0.92,
        ))

    facts["permissions"] = sorted(set(facts["permissions"]))
    return {"status": "success", **facts}


SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.BLUETOOTH_CONNECT",
}


def parse_queries_from_node(node: ET.Element) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for child in node:
        child_tag = local(child.tag)
        if child_tag == "package":
            entries.append({"kind": "package", "name": android_attr(child, "name")})
        elif child_tag == "provider":
            entries.append({"kind": "provider", "authorities": android_attr(child, "authorities")})
        elif child_tag == "intent":
            entries.append({"kind": "intent", "filter": parse_intent_filter(child)})
    return entries


def parse_application(
    element: ET.Element,
    relative: str,
    findings: list[dict[str, Any]],
    facts: dict[str, Any],
) -> None:
    attrs = stripped_attrs(element)
    app = {
        "debuggable": attrs.get("debuggable"),
        "allow_backup": attrs.get("allowBackup"),
        "uses_cleartext_traffic": attrs.get("usesCleartextTraffic"),
        "network_security_config": attrs.get("networkSecurityConfig"),
        "task_affinity": attrs.get("taskAffinity"),
        "name": attrs.get("name"),
        "full_backup_content": attrs.get("fullBackupContent"),
        "data_extraction_rules": attrs.get("dataExtractionRules"),
        "backup_agent": attrs.get("backupAgent"),
        "request_legacy_external_storage": attrs.get("requestLegacyExternalStorage"),
        "extract_native_libs": attrs.get("extractNativeLibs"),
        "has_code": attrs.get("hasCode"),
        "large_heap": attrs.get("largeHeap"),
    }
    facts["application"] = app
    facts["backup"] = {"allow_backup": app["allow_backup"]}

    if app["debuggable"] == "true":
        findings.append(build_finding(
            "manifest_debuggable", "manifest", "high",
            "Application marked debuggable",
            "The decoded manifest sets android:debuggable=true.",
            relative, None, element_tostring(element), 0.99,
        ))
    if app["uses_cleartext_traffic"] == "true":
        findings.append(build_finding(
            "manifest_cleartext_traffic", "network_security", "high",
            "Application explicitly permits cleartext traffic",
            "The decoded manifest sets android:usesCleartextTraffic=true.",
            relative, None, element_tostring(element), 0.99,
        ))

    # Backup posture: allowBackup defaults TRUE when omitted (platform doc),
    # unless rules files opt out — deduced from data we already hold.
    rules_present = bool(app["full_backup_content"] or app["data_extraction_rules"])
    if app["allow_backup"] == "true" or (app["allow_backup"] is None and not rules_present):
        findings.append(build_finding(
            "backup_enabled", "data_storage", "medium",
            "Backup/restore channel enabled",
            (
                "android:allowBackup is explicitly true." if app["allow_backup"] == "true"
                else "android:allowBackup is omitted (platform default is true) and no "
                     "backup-rules file restricts it; device transfers/cloud backups "
                     "can extract app data."
            ),
            relative, None, element_tostring(element), 0.9,
        ))
    for rule_key in ("full_backup_content", "data_extraction_rules"):
        if app[rule_key]:
            findings.append(build_finding(
                "backup_rules_referenced", "data_storage", "info",
                f"Backup rules file referenced: {app[rule_key]}",
                "Backup rule file referenced; resolved facts are attached by the analyzer.",
                relative, None, element_tostring(element), 0.95,
            ))

    meta_entries = parse_meta_data(element)
    facts["meta_data"] = meta_entries
    for entry in meta_entries:
        value = entry.get("value") or ""
        if looks_like_key(entry["name"], value):
            findings.append(build_finding(
                "meta_data_key_like_value", "secrets_hint", "info",
                f"Key-like manifest meta-data: {entry['name']}",
                "Meta-data value resembles a credential/identifier; verify against usage.",
                relative, None, f'{entry["name"]} = {entry["value"]}', 0.72,
            ))

    for component in element:
        component_type = local(component.tag)
        if component_type not in COMPONENT_TAGS:
            continue
        name = android_attr(component, "name") or "(unnamed)"
        exported = android_attr(component, "exported")
        filters = [
            parse_intent_filter(child) for child in component
            if local(child.tag) == "intent-filter"
        ]
        entry = {
            "type": component_type, "name": name, "exported": exported,
            "has_intent_filter": bool(filters), "permission": android_attr(component, "permission"),
            "intent_filters": filters,
            "attributes": stripped_attrs(component),
        }
        if component_type == "provider":
            provider = parse_provider(component)
            entry["provider"] = provider
            facts["providers"].append({"name": name, **provider})
            for authority in provider["authorities"]:
                findings.append(build_finding(
                    "content_provider_authority", "components", "info",
                    f"Content provider authority: {authority}",
                    "Provider exposes a content:// surface; review authority + grants.",
                    relative, None, element_tostring(component), 0.9,
                ))
        if filters:
            facts["intent_filters"].append({"component": name, "filters": filters})
            for target in deep_link_targets(filters):
                facts["deep_links"].append({"component": name, **target})
                findings.append(build_finding(
                    "deep_link_target", "components", "info",
                    f"Deep link target: {target['scheme']}://{target['host']}{target['path']}",
                    "Externally invocable URI surface; review handler validation.",
                    relative, None, element_tostring(component), 0.9,
                ))
        component_meta = parse_meta_data(component)
        if component_meta:
            entry["meta_data"] = component_meta
            for entry_meta in component_meta:
                if looks_like_key(entry_meta["name"], entry_meta.get("value")):
                    findings.append(build_finding(
                        "meta_data_key_like_value", "secrets_hint", "info",
                        f"Key-like component meta-data: {entry_meta['name']}",
                        "Meta-data value resembles a credential/identifier; verify against usage.",
                        relative, None, f'{entry_meta["name"]} = {entry_meta.get("value")}', 0.72,
                    ))
        facts["components"].append(entry)
        if exported == "true":
            findings.append(build_finding(
                "exported_component", "components", "medium",
                f"Exported Android component: {name}",
                "Review externally reachable component behavior, permissions, input validation, and sensitive operations.",
                relative, None, element_tostring(component), 0.94,
            ))
        elif exported is None and filters:
            findings.append(build_finding(
                "component_export_default", "components", "info",
                f"Component export behavior depends on platform/target SDK: {name}",
                "android:exported is omitted while an intent filter exists; determine effective behavior for supported Android versions.",
                relative, None, element_tostring(component), 0.83,
            ))