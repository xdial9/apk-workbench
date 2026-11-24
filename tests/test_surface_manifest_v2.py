"""S3 contracts: manifest v2 full fact map + derived findings (surface.txt 1A)."""
from __future__ import annotations

from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import deductions, manifest_v2

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.rich" android:versionCode="OOPS">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <uses-permission android:name="com.example.rich.custom"/>
  <permission android:name="com.example.rich.permission.READ"
      android:protectionLevel="signature"/>
  <application android:name="com.example.rich.App"
      android:networkSecurityConfig="@xml/network_config"
      android:allowBackup="true"
      android:fullBackupContent="@xml/backup_rules">
    <meta-data android:name="com.google.android.geo.API_KEY"
        android:value="AIzaSyD-example-key-value"/>
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="richapp" android:host="pay.example"
            android:pathPrefix="/invoice"/>
      </intent-filter>
    </activity>
    <service android:name=".Worker" android:exported="false"/>
    <provider android:name=".Files"
        android:authorities="com.example.rich.files;com.example.rich.docs"
        android:grantUriPermissions="true" android:exported="false"/>
  </application>
  <queries>
    <package android:name="com.other.app"/>
    <intent>
      <action android:name="android.intent.action.SEND"/>
    </intent>
  </queries>
</manifest>
"""

BACKUP_RULES = """<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
  <include domain="database" path="secrets.db"/>
  <exclude domain="sharedpref" path="none.xml"/>
</full-backup-content>
"""

NETWORK_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">legacy.example</domain>
  </domain-config>
  <trust-anchors>
    <certificates src="user"/>
  </trust-anchors>
</network-security-config>
"""


def _make_tree(tmp_path: Path) -> Path:
    root = tmp_path / "decode"
    (root / "res" / "xml").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST)
    (root / "res" / "xml" / "backup_rules.xml").write_text(BACKUP_RULES)
    (root / "res" / "xml" / "network_config.xml").write_text(NETWORK_CONFIG)
    return root


RULE_IDS = lambda findings: [item["rule_id"] for item in findings]


def test_manifest_v2_facts_are_complete(tmp_path):
    root = _make_tree(tmp_path)
    result = apk_surface.analyze_apk_surface(root)
    facts = result["manifest"]

    assert facts["package"] == "com.example.rich"
    assert facts["version_code"] == "OOPS"
    assert facts["shared_user_id"] is None
    assert "android.permission.ACCESS_FINE_LOCATION" in facts["permissions"]
    assert "com.example.rich.custom" in facts["permissions"]
    assert facts["permission_definitions"][0]["protectionLevel"] == "signature"
    assert facts["application"]["name"] == "com.example.rich.App"
    assert facts["application"]["full_backup_content"] == "@xml/backup_rules"

    # Deep links: scheme/host/path tuples extracted, not just counted
    assert facts["deep_links"] == [{
        "component": ".Main", "scheme": "richapp", "host": "pay.example",
        "port": "", "path": "/invoice", "mime_type": "",
    }]
    # meta-data keys AND values captured; key-like detected
    meta = facts["meta_data"][0]
    assert meta["name"] == "com.google.android.geo.API_KEY"
    assert meta["value"].startswith("AIza")
    # providers: multi-authorities + grants
    assert facts["providers"][0]["authorities"] == [
        "com.example.rich.files", "com.example.rich.docs",
    ]
    assert facts["providers"][0]["grant_uri_permissions"] == "true"
    # queries captured (package + intent kinds)
    kinds = {entry["kind"] for entry in facts["queries"]}
    assert kinds == {"package", "intent"}


def test_manifest_v2_derived_findings(tmp_path):
    root = _make_tree(tmp_path)
    result = apk_surface.analyze_apk_surface(root)
    rules = set(RULE_IDS(result["findings"]))

    assert "deep_link_target" in rules
    assert "content_provider_authority" in rules
    assert "meta_data_key_like_value" in rules
    assert "manifest_version_code_anomaly" in rules
    assert "backup_enabled" in rules                     # allowBackup=true
    assert "backup_rules_referenced" in rules
    assert "backup_include_data_domain" in rules         # include domain=database
    assert "network_config_domain_cleartext" in rules    # domain-config cleartext
    assert "network_config_user_trust_anchor" in rules   # user anchors
    assert "exported_component" in rules                 # compat kept
    assert "sensitive_permission" in rules               # compat kept
    # backup rules file facts resolved (not just referenced)
    backup = result["manifest"]["backup_rules"]["full_backup_content"]
    assert backup["status"] == "parsed"
    assert {"action": "include", "domain": "database", "path": "secrets.db"} \
        in backup["entries"]


def test_backup_default_true_deduction_when_omitted(tmp_path):
    root = tmp_path / "decode"
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.norules" android:versionCode="5">'
        "<application/></manifest>"
    )
    result = apk_surface.analyze_apk_surface(root)
    rules = set(RULE_IDS(result["findings"]))
    assert "backup_enabled" in rules
    message = next(
        item["message"] for item in result["findings"]
        if item["rule_id"] == "backup_enabled"
    )
    assert "omitted" in message                          # deduced default, cited


def test_compat_fact_keys_survive(tmp_path):
    root = _make_tree(tmp_path)
    result = apk_surface.analyze_apk_surface(root)
    facts = result["manifest"]
    assert facts["status"] == "success"
    assert facts["min_sdk"] == "24" and facts["target_sdk"] == "33"
    component = facts["components"][0]
    assert component["type"] == "activity"
    assert component["exported"] == "true"
    assert component["has_intent_filter"] is True
    # every established consumer key still present (appdev §15)
    for key in ("package", "version_code", "version_name", "min_sdk",
                "target_sdk", "permissions", "application", "components"):
        assert key in facts


def test_canonical_sensitive_permissions_shared_and_immutable():
    assert isinstance(manifest_v2.SENSITIVE_PERMISSIONS, frozenset)
    assert isinstance(deductions.PERMISSION_MISMATCH_CANDIDATES, frozenset)
    assert deductions.SENSITIVE_PERMISSIONS is manifest_v2.SENSITIVE_PERMISSIONS
    expected_12 = frozenset({
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
    })
    excluded_4 = frozenset({
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.BLUETOOTH_CONNECT",
    })
    assert deductions.PERMISSION_MISMATCH_CANDIDATES < manifest_v2.SENSITIVE_PERMISSIONS
    assert deductions.PERMISSION_MISMATCH_CANDIDATES == expected_12
    assert manifest_v2.SENSITIVE_PERMISSIONS == (expected_12 | excluded_4)


def test_permission_findings_and_mismatch_use_canonical_set(tmp_path):
    root = tmp_path / "decode"
    root.mkdir(parents=True)
    manifest_path = root / "AndroidManifest.xml"
    manifest_path.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.perms" android:versionCode="1">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.BLUETOOTH_CONNECT"/>'
        '<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>'
        '<uses-permission android:name="android.permission.INTERNET"/>'
        '<uses-permission android:name="com.example.perms.CUSTOM"/>'
        "<application/></manifest>"
    )
    findings: list[dict] = []
    parsed = manifest_v2.parse_manifest_v2(manifest_path, "AndroidManifest.xml", findings)
    perm_findings = [item for item in findings if item["category"] == "permissions"]
    assert len(perm_findings) == 5
    assert all(item["severity"] == "info" for item in perm_findings)
    sensitive_titles = [
        item["title"] for item in perm_findings if item["rule_id"] == "sensitive_permission"
    ]
    assert len(sensitive_titles) == 3
    assert any("CAMERA" in t for t in sensitive_titles)
    assert any("BLUETOOTH_CONNECT" in t for t in sensitive_titles)
    assert any("READ_EXTERNAL_STORAGE" in t for t in sensitive_titles)
    assert sum(1 for item in perm_findings if item["rule_id"] == "permission_requested") == 2

    mismatch = deductions.permission_mismatch(
        parsed["permissions"],
        {"android.permission.INTERNET"},
    )
    assert mismatch is not None
    assert "android.permission.CAMERA" in mismatch["narrative"]
    assert "android.permission.BLUETOOTH_CONNECT" not in mismatch["narrative"]
    assert "android.permission.READ_EXTERNAL_STORAGE" not in mismatch["narrative"]
    assert "android.permission.INTERNET" not in mismatch["narrative"]
    assert "com.example.perms.CUSTOM" not in mismatch["narrative"]