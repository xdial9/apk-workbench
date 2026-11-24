from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.reporting.final_run import (
    _native_evidence,
    _native_html_section,
    generate_final_run_report,
)


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
    unverified_finding = {
        "DetectorName": "UNVERIFIED_DETECTOR",
        "Verified": False,
        "Raw": "UNVERIFIED_RETAINED_FOR_AI",
    }
    (artifact_root / "trufflehog" / "findings.json").write_text(
        json.dumps([original_finding, unverified_finding]), encoding="utf-8"
    )
    static_result = {
        "schema_version": 1,
        "status": "success",
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
            "native_analysis": [
                {
                    "path": "apktool/lib/arm64-v8a/libmapped.so",
                    "state": "parsed",
                    "exports_total": 6,
                    "exports_emitted": 6,
                    "imports_total": 4,
                    "imports_emitted": 4,
                    "jni_entries": 1,
                    "jni_unmapped": 0,
                    "strings_unique": 11,
                    "strings_truncated": False,
                    "load_sites": [{"path": "apktool/smali/Main.smali", "line": 8}],
                    "load_status": "loaded",
                    "load_reason": None,
                },
                {
                    "path": "apktool/lib/arm64-v8a/libunmapped.so",
                    "state": "parse_failed",
                    "reason": "invalid ELF header",
                    "exports_total": 0,
                    "exports_emitted": 0,
                    "imports_total": 0,
                    "imports_emitted": 0,
                    "jni_entries": 0,
                    "jni_unmapped": 1,
                    "strings_unique": 0,
                    "strings_truncated": False,
                    "load_sites": [],
                    "load_status": "unreferenced",
                    "load_reason": "unreferenced",
                },
            ],
            "jni_entries": [{
                "library": "apktool/lib/arm64-v8a/libmapped.so",
                "java_class": "com.example.Main",
                "java_method": "load",
                "java_signature": "()V",
                "smali_path": "apktool/smali/com/example/Main.smali",
                "smali_line": 22,
                "confidence": "exact",
            }],
            "jni_unmapped": [{
                "library": "apktool/lib/arm64-v8a/libunmapped.so",
                "symbol": "Java_com_example_Missing_run",
                "reason": "no_matching_native_declaration",
                "offset": 64,
            }],
        },
        "metrics": {
            "native_files_found": 2,
            "native_jni_exports_total": 3,
            "native_jni_exports_mapped": 2,
            "native_jni_exports_unmapped": 1,
            "native_library_count": 2,
            "native_exports_total": 9,
            "native_imports_total": 6,
            "native_imports_emitted": 6,
            "native_strings_total": 20,
            "native_strings_emitted": 15,
            "native_strings_sharded": 5,
            "native_strings_dropped": 0,
        },
        "coverage": {
            "manifest_and_components": "success",
            "native_libraries": "partial",
            "native_strings": "sharded",
        },
        "facts": [
            {
                "kind": "native_jni_register_natives_candidate",
                "value": "apktool/lib/arm64-v8a/libmapped.so",
                "evidence": {
                    "path": "apktool/lib/arm64-v8a/libmapped.so",
                    "offset": 128,
                },
                "extra": {
                    "reason": "candidates_only_no_provable_pairing",
                },
            },
            {
                "kind": "native_export",
                "value": "apktool/lib/arm64-v8a/libmapped.so::Java_com_example_Main_load",
                "evidence": {
                    "path": "apktool/lib/arm64-v8a/libmapped.so",
                    "offset": 256,
                },
            },
            {
                "kind": "native_import",
                "value": "apktool/lib/arm64-v8a/libmapped.so::dlopen",
                "evidence": {
                    "path": "apktool/lib/arm64-v8a/libmapped.so",
                    "offset": 512,
                },
            },
        ],

        "dex_analysis": {
            "status": "success",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {"dex_files": 1, "classes": 12, "external_methods_referenced": 1},
            "external_method_references": [{
                "full_name": "Lokhttp3/Call; execute ()Lokhttp3/Response;",
                "category": "network",
                "android_api": False,
                "call_sites": [{"caller": "Lcom/example/Main; load ()V", "offset": 24}],
            }],
            "dex_api_strings": [
                {
                    "value": "https://api.example.test/v1",
                    "urls": ["https://api.example.test/v1"],
                    "domains": ["api.example.test"],
                    "route_candidate": False,
                    "relative_path_candidate": False,
                    "network_call_context": True,
                    "rate_limit_or_retry_indicator": False,
                    "http_header_candidates": [],
                    "references": [{"caller": "Lcom/example/Main; load ()V", "offset": 12}],
                },
                {
                    "value": "/catalog/products",
                    "urls": [],
                    "domains": [],
                    "route_candidate": True,
                    "relative_path_candidate": True,
                    "network_call_context": True,
                    "rate_limit_or_retry_indicator": False,
                    "http_header_candidates": [],
                    "references": [{"caller": "Lcom/example/Main; load ()V", "offset": 44}],
                },
            ],
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
    trace_chain = {
        "chain_length": 2,
        "start_node": "component:activity:com.example.Main",
        "end_node": "secret:TEST_DETECTOR",
        "edges": [
            {
                "edge_type": "method->native",
                "citations": [
                    {
                        "evidence_kind": "smali_declaration",
                        "source_path": "apktool/smali/com/example/Main.smali",
                        "line_start": 22,
                    },
                    {
                        "evidence_kind": "native_symbol",
                        "source_path": "apktool/lib/arm64-v8a/libmapped.so",
                        "byte_offset_start": 256,
                    },
                ],
            },
            {
                "edge_type": "native->secret",
                "citations": [
                    {
                        "evidence_kind": "native_library",
                        "source_path": "apktool/lib/arm64-v8a/libmapped.so",
                    },
                    {
                        "evidence_kind": "trufflehog_finding",
                        "source_path": "apktool/lib/arm64-v8a/libmapped.so",
                        "line_start": 1,
                    },
                ],
            },
        ],
    }
    (artifact_root / "trace_chains.jsonl").write_text(
        json.dumps(trace_chain) + "\n", encoding="utf-8"
    )
    native_link = {
        "edge_type": "method->native",
        "from": "method:Lcom/example/Main; load ()V",
        "to": "native:libmapped.so",
        "citations": trace_chain["edges"][0]["citations"],
    }
    unrelated_link = {
        "edge_type": "method->endpoint",
        "from": "method:Lcom/example/Main; load ()V",
        "to": "endpoint:https://api.example.test/v1",
        "citations": [],
    }
    (artifact_root / "links.jsonl").write_text(
        json.dumps(native_link) + "\n" + json.dumps(unrelated_link) + "\n",
        encoding="utf-8",
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
    # Native plane: the run report proves the JNI surface was analysed and
    # that the mapping identity closed (3 = 2 mapped + 1 unmapped-with-reason).
    native_stage = payload["stages"]["static_apk_surface_analysis"]
    assert native_stage["native_files_found"] == 2
    assert native_stage["native_jni_exports_total"] == 3
    assert native_stage["native_jni_exports_mapped"] == 2
    assert native_stage["native_jni_exports_unmapped"] == 1
    assert native_stage["native_jni_mapping_complete"] is True
    assert native_stage["native_strings_total"] == 20
    assert native_stage["native_strings_emitted"] == 15
    assert native_stage["native_strings_sharded"] == 5
    native_evidence = payload["artifacts"][0]["native_evidence"]
    assert native_evidence["status"] == "partial"
    assert native_evidence["libraries"][1]["state"] == "parse_failed"
    assert native_evidence["jni_unmapped"][0]["reason"] == (
        "no_matching_native_declaration"
    )
    assert native_evidence["exports"][0]["value"].endswith(
        "Java_com_example_Main_load"
    )
    assert native_evidence["imports"][0]["value"].endswith("::dlopen")
    assert native_evidence["trace_chains"][0] == trace_chain
    assert native_evidence["links"][0] == native_link
    assert len(native_evidence["links"]) == 1
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
    assert payload["summary"]["androguard_dex_route_candidates"] == 1
    assert payload["summary"]["androguard_relative_path_candidates"] == 1
    assert payload["stages"]["static_apk_surface_analysis"]["androguard_dex_route_candidates"] == 1
    assert payload["summary"]["api_smali_call_sites"] == 1
    html_text = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "API inventory" in html_text
    assert "Smali network/API call sites" in html_text
    assert "TruffleHog verified findings (1)" in html_text
    assert "Androguard DEX cross-reference inventory" in html_text
    assert "Network-call context" in html_text
    assert "/catalog/products" in html_text
    assert "Lokhttp3/Call; execute ()Lokhttp3/Response;" in html_text
    assert "Native analysis" in html_text
    assert "Native library inventory" in html_text
    assert "invalid ELF header" in html_text
    assert "no_matching_native_declaration" in html_text
    assert "Dynamic JNI registration candidate" in html_text
    assert "libmapped.so@0x100" in html_text
    assert "JNI exports mapped to Java methods" in html_text
    assert "Java_com_example_Main_load" in html_text
    assert "::dlopen" in html_text
    native_section = html_text.split("<h4>Native analysis</h4>", 1)[1].split(
        "<h4>Static-analysis coverage</h4>", 1
    )[0]
    assert "ORIGINAL_VALUE_PRESERVED" not in native_section
    assert payload["artifacts"][0]["findings"]["trufflehog_verified_original_objects"][0] == original_finding
    # Unverified records are counted and retained, not reported as verified and
    # not allowed to abort the run.
    assert payload["artifacts"][0]["findings"]["trufflehog_unverified_count"] == 1
    assert payload["summary"]["unverified_trufflehog_findings_retained"] == 1
    assert payload["stages"]["trufflehog_verified_secret_scan"]["unverified_findings_retained"] == 1
    assert "results=<complete set>" in payload["stages"]["trufflehog_verified_secret_scan"]["selection"]
    assert "UNVERIFIED_DETECTOR" not in json.dumps(
        payload["artifacts"][0]["findings"]["trufflehog_verified_original_objects"]
    )
    assert Path(result["html_path"]).is_file()


def test_final_run_report_skips_surface_evidence_when_decompile_failed(tmp_path):
    # When decompilation produces no usable Apktool output, surface analysis is
    # legitimately skipped and writes no static-analysis.json. The consolidated
    # report must not treat that as a fatal "analysis succeeded without a
    # result" inconsistency; it records the artifact as not-run and still
    # produces a report.
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()
    run_id = "decompile-failed-run"
    package_id = "com.example.app"
    version_code = "17"
    apk_bytes = b"decompile failed fixture"
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = workspace / "downloads" / package_id / "17" / digest / "base.apk"
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
    # Decompilation failed -> no apktool dir, no surface output.
    database.update_processing_status({
        "sha256": digest,
        "package_id": package_id,
        "version_code": version_code,
        "apktool_status": "failed",
        "scan_status": "pending",
    })
    (workspace / "reports").mkdir(parents=True, exist_ok=True)

    result = generate_final_run_report(database, workspace, run_id)

    assert result["artifact_count"] == 1
    payload = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    artifact = payload["artifacts"][0]
    assert artifact["static_analysis"]["status"] == "not_run"
    assert artifact["processing"]["apktool_status"] == "failed"
    assert artifact["native_evidence"]["status"] == "not_run"
    assert "Native analysis was not run" in Path(result["html_path"]).read_text(
        encoding="utf-8"
    )


def test_native_report_states_distinguish_absent_failed_and_not_run():
    absent = _native_evidence(
        {"status": "success", "coverage": {"native_libraries": "not_found"}},
        [],
        [],
    )
    failed = _native_evidence(
        {"status": "failed", "coverage": {"native_libraries": "failed"}},
        [],
        [],
    )
    not_run = _native_evidence(None, None, None)

    assert absent["status"] == "not_present"
    assert "No native libraries were present" in "\n".join(
        _native_html_section(absent)
    )
    assert failed["status"] == "failed"
    assert "Native analysis failed" in "\n".join(_native_html_section(failed))
    assert not_run["status"] == "not_run"
    assert "Native analysis was not run" in "\n".join(
        _native_html_section(not_run)
    )


def test_final_run_report_still_fails_when_surface_succeeded_but_missing(tmp_path):
    # The genuine inconsistency still stays fatal: apktool succeeded, so the
    # surface analyzer was expected to run, but static-analysis.json is absent.
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()
    run_id = "missing-surface-run"
    package_id = "com.example.app"
    version_code = "17"
    apk_bytes = b"missing surface fixture"
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = workspace / "downloads" / package_id / "17" / digest / "base.apk"
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
    database.update_processing_status({
        "sha256": digest,
        "package_id": package_id,
        "version_code": version_code,
        "apktool_status": "success",
        "scan_status": "success",
    })
    (workspace / "reports").mkdir(parents=True, exist_ok=True)

    from apkworkbench.reporting.final_run import FinalRunReportError

    with pytest.raises(FinalRunReportError, match="static-analysis.json is missing"):
        generate_final_run_report(database, workspace, run_id)


def test_final_run_report_reads_surface_links_and_trace_chains(tmp_path):
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()
    run_id = "surface-layout-run"
    package_id = "com.example.surface"
    version_code = "3"
    apk_bytes = b"surface layout fixture"
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = workspace / "downloads" / package_id / version_code / digest / "base.apk"
    apk_path.parent.mkdir(parents=True)
    apk_path.write_bytes(apk_bytes)
    row = {
        "run_id": run_id,
        "selection_order": 1,
        "selected_at": "2026-11-10T12:00:00+00:00",
        "package_id": package_id,
        "app_name": "Surface App",
        "version_code": version_code,
        "version_name": "3.0",
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
    (artifact_root / "trufflehog" / "findings.json").write_text("[]", encoding="utf-8")
    surface_dir = artifact_root / "surface"
    surface_dir.mkdir(parents=True)
    (surface_dir / "static-analysis.json").write_text(
        json.dumps({"schema_version": 1, "status": "success", "findings": [], "coverage": {"native_libraries": "partial"}}),
        encoding="utf-8",
    )
    trace_chain = {"chain_length": 1, "edges": [{"edge_type": "method->native", "citations": []}]}
    native_link = {"edge_type": "method->native", "from": "m", "to": "n", "citations": []}
    (surface_dir / "trace_chains.jsonl").write_text(json.dumps(trace_chain) + "\n", encoding="utf-8")
    (surface_dir / "links.jsonl").write_text(json.dumps(native_link) + "\n", encoding="utf-8")
    (artifact_root / "manifest").mkdir(parents=True)
    (artifact_root / "manifest" / "google-play-bundle.json").write_text(
        json.dumps({"source": "google_play", "package_id": package_id}), encoding="utf-8"
    )

    result = generate_final_run_report(database, workspace, run_id)
    payload = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    native_evidence = payload["artifacts"][0]["native_evidence"]
    assert native_evidence["trace_chains"] == [trace_chain]
    assert native_evidence["links"] == [native_link]
    assert payload["artifacts"][0]["acquisition"]["bundle_metadata"]["package_id"] == package_id
