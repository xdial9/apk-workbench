"""S6 contracts: finalize/workbook + version bump + reuse-gate staleness."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path


from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import workbook as wb


def test_finalize_result_adds_workbook_and_distinct_metrics():
    result = {
        "findings": [
            {"rule_id": "r1", "evidence": {"path": "a.smali", "line": 3}},
            {"rule_id": "r1", "evidence": {"path": "a.smali", "line": 3}},   # dup
            {"rule_id": "r2", "evidence": {"path": "b.xml", "line": 9}},
        ],
        "facts": [{"kind": "endpoint", "value": "https://a.b/"}],
        "deductions": [{"id": "D-X", "narrative": "n", "cites": ["endpoint:x"]}],
        "coverage": {"smali_security_indicators": "success",
                     "runtime_behavior": "not_performed"},
    }
    finalized = apk_surface.finalize_result(result)
    metrics = finalized["metrics"]
    assert metrics["distinct_finding_count"] == 2      # duplicate merged
    assert metrics["fact_count"] == 1
    assert metrics["deduction_count"] == 1

    book = finalized["workbook"]
    assert "analyst" in book["mission"].lower()
    assert book["confidence_labels"] == wb.CONFIDENCE_LABELS
    assert book["permission_map"]["working_area"] == "ai_analysis/"
    # location ledger cites findings with file:line
    finding_entries = book["location_ledger"]["findings"]
    assert {"a.smali:3", "b.xml:9"} <= {
        entry["location"] for entry in finding_entries
    }
    # leads: coverage gap (runtime_behavior) becomes a lead; deduction is a lead
    lead_ids = {lead["id"] for lead in book["playbook"]["open_leads"]}
    assert "COV-runtime_behavior" in lead_ids
    assert "D-X" in lead_ids
    # finish line present + checklist
    assert book["finish_line"]["checklist"]


def test_analyzer_version_bumped_and_consumers_intact(tmp_path):
    root = tmp_path / "decode"
    (root / "smali").mkdir(parents=True)
    (root / "smali" / "A.smali").write_text("setJavaScriptEnabled(true)\n")
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.v" android:versionCode="1"><application/></manifest>'
    )
    result = apk_surface.analyze_apk_surface(root)
    assert result["analyzer"] == {"id": "apk-surface", "version": "0.3.0"}
    # consumer keys (appdev §15) still present
    for key in ("manifest", "inventory", "findings", "coverage", "status",
                "facts", "deductions", "workbook"):
        assert key in result


class _StubDatabase:
    def __init__(self, rows, statuses):
        self._rows = rows
        self._statuses = statuses

    def read_download_history(self):
        return self._rows

    def read_processing_status(self):
        return self._statuses

    def read_manifest(self, run_id):
        if run_id != "run-s6":
            return []
        return [{
            "run_id": run_id, "selection_order": 1,
            "package_id": "com.example.s6", "version_code": "1",
            "source": "google_play", "sha256": _DIGEST,
        }]


_DIGEST = None


def _prepare_artifact(tmp_path: Path) -> tuple[Path, dict]:
    workspace = tmp_path / "workspace"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex\n000")
    apk_bytes = buffer.getvalue()
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = workspace / "downloads" / "com.example.s6-1" / digest / "app.apk"
    apk_path.parent.mkdir(parents=True)
    apk_path.write_bytes(apk_bytes)
    decoded = workspace / "results" / "com.example.s6" / "1" / digest / "apktool"
    decoded.mkdir(parents=True)
    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.s6" android:versionCode="1"><application/></manifest>'
    )
    (decoded / "smali").mkdir()
    (decoded / "smali" / "A.smali").write_text("const-string v0, \"https://s6.example.net/api\"\n")
    history_row = {
        "sha256": digest, "package_id": "com.example.s6", "version_code": "1",
        "version_name": "1.0", "source": "google_play", "run_id": "run-s6",
        "local_path": str(apk_path), "size": apk_path.stat().st_size,
    }
    statuses = {digest: {"apktool_status": "success"}}
    global _DIGEST
    _DIGEST = digest
    return workspace, {
        "workspace": workspace, "history_row": history_row,
        "statuses": statuses, "digest": digest,
    }


def test_driver_writes_workbook_and_rejects_stale_reuse(monkeypatch, tmp_path):
    workspace, ctx = _prepare_artifact(tmp_path)
    database = _StubDatabase([ctx["history_row"]], ctx["statuses"])
    monkeypatch.setattr(
        apk_surface, "analyze_apk_dex",
        lambda apk_path, timeout_seconds=1800, progress=None: {
            "status": "success", "diagnostics": [], "limitations": [],
            "metrics": {}, "permission_api_usage": [],
        },
    )

    summary = apk_surface.run_static_surface_analysis(
        database, workspace, run_id="run-s6", progress=lambda _m: None,
    )
    assert summary["completed"] == 1

    target = (
        workspace / "results" / "com.example.s6" / "1" / ctx["digest"]
        / "static-analysis.json"
    )
    stored = json.loads(target.read_text(encoding="utf-8"))
    assert stored["analyzer"]["version"] == "0.3.0"
    assert "workbook" in stored and stored["workbook"]["mission"]
    leads = stored["workbook"]["playbook"]["open_leads"]
    # the sweep found a public URL endpoint; the api-surface deduction is a lead
    assert any(lead["id"] == "D-API-SURFACE" for lead in leads)

    # a stale 0.2.0 result must be re-analyzed, not reused
    stored["analyzer"]["version"] = "0.2.0"
    target.write_text(json.dumps(stored), encoding="utf-8")
    summary2 = apk_surface.run_static_surface_analysis(
        database, workspace, run_id="run-s6", progress=lambda _m: None,
    )
    assert summary2["completed"] == 1
    refreshed = json.loads(target.read_text(encoding="utf-8"))
    assert refreshed["analyzer"]["version"] == "0.3.0"

    # a same-version result is reused (skip-reuse)
    summary3 = apk_surface.run_static_surface_analysis(
        database, workspace, run_id="run-s6", progress=lambda _m: None,
    )
    assert summary3["skipped"] == 1