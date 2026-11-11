from __future__ import annotations

import hashlib
import json
from pathlib import Path

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.reporting.final_run import generate_final_run_report


def test_final_run_report_consolidates_every_stage_api_catalog_and_complete_findings(tmp_path):
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()
    run_id = "final-report-run"
    package_id = "com.example.app"
    version_code = "17"
    apk_bytes = b"complete final report fixture"
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = workspace / "downloads" / package_id / version_code / digest / "base.apk"
    apk_path.parent.mkdir(parents=True)
    apk_path.write_bytes(apk_bytes)
    row = {
        "run_id": run_id,
        "selection_order": 1,
        "selected_at": "2026-11-10T12:00:00+00:00",
        "package_id": package_id,
        "app_name": "Example",
        "version_code": version_code,
        "version_name": "17.0",
        "source": "google_play",
        "download_url": "google-play://example/base.apk",
        "sha256": digest,
        "size": len(apk_bytes),
        "signer_sha256": "a" * 64,
        "local_path": str(apk_path),
        "index_sha256": "b" * 64,
    }
    database.write_manifest(run_id, [row])
    database.append_history({**row, "downloaded_at": "2026-11-10T12:01:00+00:00"})
    bundle = {
        "source": "google_play",
        "run_id": run_id,
        "package_id": package_id,
        "version_code": int(version_code),
        "files": [{"name": "base.apk", "kind": "apk", "sha256": digest}],
    }
    (apk_path.parent / "google-play-bundle.json").write_text(
        json.dumps(bundle), encoding="utf-8"
    )
    database.update_processing_status({
        "sha256": digest,
        "package_id": package_id,
        "version_code": version_code,
        "apktool_status": "success",
        "scan_status": "success",
    })

    artifact_root = workspace / "results" / package_id / version_code / digest
    (artifact_root / "apktool").mkdir(parents=True)
    (artifact_root / "trufflehog").mkdir(parents=True)
    original_finding = {
        "DetectorName": "TEST_DETECTOR",
        "Verified": True,
        "Raw": "ORIGINAL_VALUE_PRESERVED",
        "ExtraData": {"complete": "object"},
    }
    (artifact_root / "trufflehog" / "findings.json").write_text(
        json.dumps([original_finding]), encoding="utf-8"
    )
    static_result = {
        "schema_version": 1,
        "status": "success",
        "coverage": {"manifest_and_components": "success"},
        "inventory": {
            "endpoints": [{
                "value": "https://api.example.test/v1",
                "kind": "url",
                "evidence": [{"path": "smali/Main.smali", "line": 12}],
            }],
            "api_routes": [{
                "path": "/v1/accounts",
                "http_method": "GET",
                "evidence": [{"path": "smali/Main.smali", "line": 13}],
            }],
            "api_clients": [{"name": "Retrofit", "call_sites": [], "call_site_count": 1}],
            "api_call_sites": [{
                "owner": "Lokhttp3/Call;", "method": "execute",
                "path": "smali/Main.smali", "line": 15,
            }],
            "api_headers": [{"name": "retry-after", "evidence": []}],
            "rate_limit_indicators": [{"path": "smali/Main.smali", "line": 14}],
        },
        "dex_analysis": {
            "status": "success",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {"dex_files": 1, "classes": 12, "external_methods_referenced": 1},
            "external_method_references": [{
                "full_name": "Lokhttp3/Call; execute ()Lokhttp3/Response;",
                "category": "network",
                "call_sites": [{"caller": "Lcom/example/Main; load ()V", "offset": 24}],
            }],
            "dex_api_strings": [{
                "value": "https://api.example.test/v1",
                "urls": ["https://api.example.test/v1"],
                "references": [{"caller": "Lcom/example/Main; load ()V", "offset": 12}],
            }],
            "permission_api_usage": [{
                "api_method": "Landroid/location/LocationManager; getLastKnownLocation",
                "permissions": ["android.permission.ACCESS_FINE_LOCATION"],
                "call_sites": [],
            }],
        },
        "findings": [{"rule_id": "exported_component", "verification_state": "static_unverified"}],
    }
    (artifact_root / "static-analysis.json").write_text(
        json.dumps(static_result), encoding="utf-8"
    )
    reports_root = workspace / "reports"
    reports_root.mkdir(parents=True)
    (reports_root / f"phase_one_verification_{run_id}.json").write_text(
        json.dumps({"status": "verified", "bundles": [{
            "package_id": package_id,
            "version_code": int(version_code),
            "apk_components": 1,
            "obb_components": 0,
        }]}),
        encoding="utf-8",
    )

    result = generate_final_run_report(database, workspace, run_id)

    payload = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    assert result["artifact_count"] == 1
    assert result["verified_findings"] == 1
    assert result["static_findings"] == 1
    assert result["api_endpoint_count"] == 1
    assert result["api_route_count"] == 1
    assert payload["stages"]["independent_download_verification"]["status"] == "verified"
    assert payload["stages"]["reconciliation"]["complete"] == 1
    assert payload["api_catalog"]["endpoint_candidates"][0]["value"] == "https://api.example.test/v1"
    assert payload["api_catalog"]["route_candidates"][0]["path"] == "/v1/accounts"
    assert payload["api_catalog"]["client_library_evidence"][0]["name"] == "Retrofit"
    assert payload["api_catalog"]["smali_api_call_sites"][0]["method"] == "execute"
    assert payload["api_catalog"]["client_rate_limit_and_retry_indicators"]
    assert payload["api_catalog"]["androguard_external_method_references"][0]["category"] == "network"
    assert payload["api_catalog"]["androguard_api_related_strings"][0]["value"] == "https://api.example.test/v1"
    assert payload["api_catalog"]["androguard_permission_api_usage"][0]["permissions"][0] == "android.permission.ACCESS_FINE_LOCATION"
    assert payload["summary"]["androguard_external_method_references"] == 1
    assert payload["summary"]["api_smali_call_sites"] == 1
    html_text = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "API inventory" in html_text
    assert "Smali network/API call sites" in html_text
    assert "TruffleHog verified findings (1)" in html_text
    assert "Androguard DEX cross-reference inventory" in html_text
    assert "Lokhttp3/Call; execute ()Lokhttp3/Response;" in html_text
    assert payload["artifacts"][0]["findings"]["trufflehog_verified_original_objects"][0] == original_finding
    assert Path(result["html_path"]).is_file()
