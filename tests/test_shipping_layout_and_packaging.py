"""Regression tests for single-folder layout, bundled data, doctor, migration, and packaging."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import textwrap
import zipfile
from pathlib import Path

import yaml
from click.testing import CliRunner

import apkworkbench
from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import handoff
from apkworkbench.cli import main as cli
from apkworkbench.core.config import Config
from apkworkbench.core.layout import (
    _copy_tree_preserving_readonly,
    migrate_legacy_workspace,
    run_local_apk_self_contained,
)
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.dependencies.detector import DependencyDetector, DependencyInfo

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def _make_synthetic_apk(path: Path) -> Path:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex\n035\x00synthetic")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(stream.getvalue())
    return path


def _make_synthetic_tools(tmp_path: Path) -> tuple[Path, Path]:
    apktool = _write_executable(
        tmp_path / "apktool-fixture",
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import pathlib
            import sys

            args = sys.argv[1:]
            if "--version" in args:
                print("2.9.3")
                raise SystemExit(0)
            output = pathlib.Path(args[args.index("-o") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.shipping"><application><activity '
                'android:name="com.example.shipping.Main" android:exported="true" />'
                "</application></manifest>",
                encoding="utf-8",
            )
            smali = output / "smali/com/example/shipping"
            smali.mkdir(parents=True)
            (smali / "Main.smali").write_text(
                ".class public Lcom/example/shipping/Main;\\n"
                ".super Ljava/lang/Object;\\n"
                ".method public onCreate()V\\n"
                "    .locals 0\\n"
                "    return-void\\n"
                ".end method\\n",
                encoding="utf-8",
            )
            print("Apktool synthetic fixture completed")
            """
        ),
    )
    trufflehog = _write_executable(
        tmp_path / "trufflehog-fixture",
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import sys

            if "--version" in sys.argv[1:]:
                print("trufflehog 3.82.0")
                raise SystemExit(0)
            if len(sys.argv) > 2 and sys.argv[2] == "--help":
                print(
                    "filesystem --results=RESULTS --no-update --json "
                    "--concurrency --fail-on-scan-errors"
                )
                raise SystemExit(0)
            finding = {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "smali/com/example/shipping/Main.smali",
                            "line": 4,
                        }
                    }
                },
                "DetectorType": 2,
                "DetectorName": "SYNTHETIC_TEST",
                "DecoderName": "PLAIN",
                "Verified": True,
                "Raw": "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED",
            }
            print(json.dumps(finding))
            """
        ),
    )
    return apktool, trufflehog


def _stub_dex_result() -> dict:
    return {
        "status": "success",
        "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
        "metrics": {"dex_files": 1, "external_methods_referenced": 1},
        "coverage": {"dex_parsing": "success"},
        "class_model": [
            {
                "class_name": "Lcom/example/shipping/Main;",
                "dex_index": 0,
                "source_file": "Main.java",
            }
        ],
        "method_model": [
            {
                "full_name": "Lcom/example/shipping/Main; onCreate ()V",
                "class_name": "Lcom/example/shipping/Main;",
                "dex_index": 0,
                "method_name": "onCreate",
                "descriptor": "()V",
            }
        ],
        "external_method_references": [
            {
                "full_name": "Lokhttp3/Call; execute ()",
                "category": "network",
                "callers": ["Lcom/example/shipping/Main; onCreate ()V"],
            }
        ],
        "internal_call_graph": [],
        "dex_api_strings": [],
        "reflection_sites": [],
        "permission_api_usage": [],
        "string_class_index": {},
        "diagnostics": [],
        "limitations": [],
    }


def _make_writable_tree(root: Path) -> None:
    """Restore write bits so pytest tmp_path cleanup never hits frozen dirs."""
    if not root.exists():
        return
    for current, dirs, files in os.walk(root):
        cur = Path(current)
        os.chmod(cur, stat.S_IMODE(cur.stat().st_mode) | 0o700)
        for name in files:
            fpath = cur / name
            if not fpath.is_symlink():
                os.chmod(fpath, stat.S_IMODE(fpath.stat().st_mode) | 0o600)


def test_self_contained_local_apk_layout_and_portability(monkeypatch, tmp_path):
    monkeypatch.setattr(apk_surface, "analyze_apk_dex", lambda _path, **_kwargs: _stub_dex_result())

    apk_path = _make_synthetic_apk(tmp_path / "input" / "sample.apk")
    apktool, trufflehog = _make_synthetic_tools(tmp_path / "tools")
    home = tmp_path / "home"
    home.mkdir()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "tools": {
                    "apktool": str(apktool),
                    "trufflehog": str(trufflehog),
                }
            }
        ),
        encoding="utf-8",
    )
    config = Config(config_file=cfg_path, workspace=home)

    result = run_local_apk_self_contained(
        apk_path,
        home,
        config=config,
        package_id="com.example.shipping",
        version_code=7,
        version_name="1.7.0",
        run_id="ship1234-run-id",
    )

    try:
        top_entries = {entry.name for entry in home.iterdir()}
        assert top_entries <= {"runs", "runs_index.json", "logs"}
        assert "runs" in top_entries
        assert "runs_index.json" in top_entries
        for forbidden in ("downloads", "results", "database", "reports"):
            assert not (home / forbidden).exists(), f"Unexpected top-level dir: {forbidden}"

        run_dirs = list((home / "runs").iterdir())
        assert len(run_dirs) == 1
        run_dir = run_dirs[0]
        assert Path(result["run_dir"]) == run_dir

        expected_files = [
            "apk/base.apk",
            "surface/static-analysis.json",
            "surface/facts.jsonl",
            "surface/location_map.json",
            "trufflehog/findings.json",
            "reports/final-report.json",
            "reports/final-report.html",
            "README.md",
            "README.txt",
            "handoff.json",
            "hashes.sha256",
            *(f"prompts/{idx}.txt" for idx in range(7)),
        ]
        for rel in expected_files:
            assert (run_dir / rel).is_file(), f"Missing expected file: {rel}"

        for rel_dir in ("apktool", "manifest", "stages", "logs", "ai_analysis/attempt-01"):
            assert (run_dir / rel_dir).is_dir(), f"Missing expected directory: {rel_dir}"

        readme_text = (run_dir / "README.md").read_text(encoding="utf-8")
        assert "com.example.shipping" in readme_text
        assert "1.7.0 (7)" in readme_text
        assert "ship1234-run-id" in readme_text
        assert "dossier.md" in readme_text
        assert "lead_ledger.json" in readme_text

        index_data = json.loads((home / "runs_index.json").read_text(encoding="utf-8"))
        assert len(index_data["runs"]) == 1
        entry = index_data["runs"][0]
        assert entry["package_id"] == "com.example.shipping"
        assert entry["folder"] == f"runs/{run_dir.name}"

        # Copy the single run folder to an isolated temp directory and verify portability.
        copied = tmp_path / "copied-run"
        _copy_tree_preserving_readonly(run_dir, copied)
        verification = WorkspaceDatabase(tmp_path).verify_workspace(copied)
        assert verification["status"] == "ok", verification
    finally:
        _make_writable_tree(home)
        _make_writable_tree(tmp_path / "copied-run")


def test_cli_run_local_apk_self_contained(monkeypatch, tmp_path):
    monkeypatch.setattr(apk_surface, "analyze_apk_dex", lambda _path, **_kwargs: _stub_dex_result())

    apk_path = _make_synthetic_apk(tmp_path / "input" / "cli-sample.apk")
    apktool, trufflehog = _make_synthetic_tools(tmp_path / "tools")
    cli_home = tmp_path / "cli-home"
    cli_home.mkdir()
    (cli_home / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": {
                    "apktool": str(apktool),
                    "trufflehog": str(trufflehog),
                }
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(
        cli.main,
        [
            "--workspace",
            str(cli_home),
            "run",
            "--local-apk",
            str(apk_path),
            "--package",
            "com.example.clirun",
        ],
    )
    try:
        assert res.exit_code == 0, res.output
        assert "SELF-CONTAINED RUN COMPLETE" in res.output
        for forbidden in ("downloads", "results", "database", "reports"):
            assert not (cli_home / forbidden).exists()
        run_dirs = list((cli_home / "runs").iterdir())
        assert len(run_dirs) == 1
        assert (cli_home / "runs_index.json").is_file()
        assert (run_dirs[0] / "README.md").is_file()
        assert (run_dirs[0] / "hashes.sha256").is_file()
    finally:
        _make_writable_tree(cli_home)


def test_bundled_package_data_and_license(monkeypatch, tmp_path):
    license_path = REPO_ROOT / "LICENSE"
    assert license_path.is_file()
    license_text = license_path.read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "2026 xdial9" in license_text

    bundled_prompts = REPO_ROOT / "src" / "apkworkbench" / "data" / "prompts"
    repo_prompts = REPO_ROOT / "prompts"
    for idx in range(7):
        name = f"{idx}.txt"
        bundled = bundled_prompts / name
        original = repo_prompts / name
        assert bundled.is_file(), f"Missing bundled prompt: {name}"
        assert original.is_file(), f"Missing repo prompt: {name}"
        assert bundled.read_bytes() == original.read_bytes(), f"Prompt mismatch: {name}"

    example_cfg = REPO_ROOT / "src" / "apkworkbench" / "data" / "config.example.yaml"
    assert example_cfg.is_file()
    loaded = yaml.safe_load(example_cfg.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    assert "tools" in loaded

    # Simulate an installed wheel layout where no ancestor <repo>/prompts exists.
    fake_pkg = tmp_path / "site-packages" / "apkworkbench"
    fake_handoff = fake_pkg / "analysis" / "surface" / "handoff.py"
    fake_handoff.parent.mkdir(parents=True)
    fake_handoff.write_text("# synthetic", encoding="utf-8")
    fake_data_prompts = fake_pkg / "data" / "prompts"
    fake_data_prompts.mkdir(parents=True)
    (fake_data_prompts / "0.txt").write_text("bundled master prompt", encoding="utf-8")

    monkeypatch.delenv("APKWORKBENCH_PROMPTS_DIR", raising=False)
    monkeypatch.setattr(handoff, "__file__", str(fake_handoff))
    assert handoff.prompts_source_dir() == fake_data_prompts


def test_doctor_all_ok_missing_hints_and_legacy_config_note(monkeypatch, tmp_path):
    fake_user_home = tmp_path / "user-home"
    fake_user_home.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("HOME", str(fake_user_home))
    monkeypatch.setattr(
        cli,
        "_doctor_auth_report",
        lambda _cfg: {"configured_mode": "auto", "resolved_mode": "account", "account_source": "env", "account_email": "test@example.com"},
    )

    all_ok_deps = [
        DependencyInfo(
            name=name,
            required=True,
            executable=name,
            installed=True,
            healthy=True,
            version="1.0.0",
            install_hint=DependencyDetector.INSTALL_HINTS.get(name),
        )
        for name in DependencyDetector.CHECKS
    ]
    monkeypatch.setattr(DependencyDetector, "detect_all", lambda _self: all_ok_deps)

    runner = CliRunner()
    res_ok = runner.invoke(cli.main, ["--workspace", str(workspace), "doctor"])
    assert res_ok.exit_code == 0, res_ok.output
    for name in DependencyDetector.CHECKS:
        assert f"[OK] {name}" in res_ok.output
    assert "[OK] workspace" in res_ok.output
    assert "[OK] prompts" in res_ok.output
    assert "Status: READY" in res_ok.output

    # Missing apktool and trufflehog -> exit 1 with Install: hints
    missing_deps = [
        DependencyInfo(
            name=name,
            required=True,
            executable=name,
            installed=name not in {"apktool", "trufflehog"},
            healthy=name not in {"apktool", "trufflehog"},
            version=None if name in {"apktool", "trufflehog"} else "1.0.0",
            error=f"Executable {name!r} was not found." if name in {"apktool", "trufflehog"} else None,
            install_hint=DependencyDetector.INSTALL_HINTS.get(name),
        )
        for name in DependencyDetector.CHECKS
    ]
    monkeypatch.setattr(DependencyDetector, "detect_all", lambda _self: missing_deps)

    res_missing = runner.invoke(cli.main, ["--workspace", str(workspace), "doctor"])
    assert res_missing.exit_code == 1, res_missing.output
    assert "[MISSING] apktool" in res_missing.output
    assert "[MISSING] trufflehog" in res_missing.output
    assert f"Install: {DependencyDetector.INSTALL_HINTS['apktool']}" in res_missing.output
    assert f"Install: {DependencyDetector.INSTALL_HINTS['trufflehog']}" in res_missing.output
    assert "Status: MISSING OR UNHEALTHY REQUIRED DEPENDENCIES" in res_missing.output

    # Legacy ~/.config/apkworkbench/config.yaml note
    legacy_cfg = fake_user_home / ".config" / "apkworkbench" / "config.yaml"
    legacy_cfg.parent.mkdir(parents=True)
    legacy_cfg.write_text("logging:\n  level: INFO\n", encoding="utf-8")
    monkeypatch.setattr(DependencyDetector, "detect_all", lambda _self: all_ok_deps)

    res_legacy = runner.invoke(cli.main, ["--workspace", str(workspace), "doctor"])
    assert res_legacy.exit_code == 0, res_legacy.output
    assert "reading legacy config from" in res_legacy.output
    assert str(legacy_cfg) in res_legacy.output


def test_migrate_legacy_workspace_dry_run_and_cli_apply(monkeypatch, tmp_path):
    fake_user_home = tmp_path / "user-home"
    legacy_cfg = fake_user_home / ".config" / "apkworkbench" / "config.yaml"
    legacy_cfg.parent.mkdir(parents=True)
    legacy_cfg.write_text("logging:\n  level: DEBUG\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_user_home))

    source_ws = tmp_path / "legacy-ws"
    digest = hashlib.sha256(b"legacy-apk").hexdigest()
    bundle_dir = source_ws / "results" / "com.example.app" / "1" / digest
    for subdir in ("apktool", "surface", "trufflehog", "manifest"):
        (bundle_dir / subdir).mkdir(parents=True, exist_ok=True)
    (bundle_dir / "apktool" / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (bundle_dir / "surface" / "static-analysis.json").write_text("{}", encoding="utf-8")
    (bundle_dir / "trufflehog" / "findings.json").write_text("[]", encoding="utf-8")
    (bundle_dir / "manifest" / "google-play-bundle.json").write_text(
        json.dumps({"package_id": "com.example.app", "version_code": 1, "version_name": "1.0"}),
        encoding="utf-8",
    )

    ai_dir = bundle_dir / "ai_analysis" / "attempt-01"
    ai_dir.mkdir(parents=True, exist_ok=True)
    dossier_bytes = b"# Dossier\n\nVerified finding evidence.\n"
    ledger_bytes = b'{"leads": [{"id": "L1", "status": "confirmed"}]}\n'
    (ai_dir / "dossier.md").write_bytes(dossier_bytes)
    (ai_dir / "lead_ledger.json").write_bytes(ledger_bytes)

    # Freeze evidence dirs read-only like a real legacy bundle.
    for subdir in ("apktool", "surface", "trufflehog", "manifest"):
        for item in (bundle_dir / subdir).iterdir():
            os.chmod(item, 0o444)
        os.chmod(bundle_dir / subdir, 0o555)

    downloads_dir = source_ws / "downloads" / "com.example.app-1"
    downloads_dir.mkdir(parents=True)
    apk_bytes = b"PK\x03\x04fake-apk"
    (downloads_dir / "base.apk").write_bytes(apk_bytes)

    target_home = tmp_path / "new-home"

    try:
        # 1. Dry-run: target must remain untouched
        dry_report = migrate_legacy_workspace(
            source_ws,
            target_home,
            dry_run=True,
            legacy_config_path=legacy_cfg,
        )
        assert dry_report["dry_run"] is True
        assert dry_report["bundles_found"] == 1
        assert dry_report["bundles_migrated"] == 0
        assert dry_report["dossiers_found"] == 1
        assert dry_report["lead_ledgers_found"] == 1
        assert not target_home.exists()

        # 2. Apply via CLI
        runner = CliRunner()
        res = runner.invoke(
            cli.main,
            [
                "migrate",
                "--source",
                str(source_ws),
                "--target",
                str(target_home),
                "--apply",
            ],
        )
        assert res.exit_code == 0, res.output
        assert "WORKSPACE MIGRATION (APPLY)" in res.output
        assert "Bundles discovered: 1" in res.output
        assert "Bundles migrated: 1" in res.output
        assert "Dossiers found / verified: 1 / 1" in res.output
        assert "Lead ledgers found / verified: 1 / 1" in res.output

        # Source untouched
        assert (bundle_dir / "ai_analysis" / "attempt-01" / "dossier.md").read_bytes() == dossier_bytes
        assert (downloads_dir / "base.apk").read_bytes() == apk_bytes
        assert legacy_cfg.is_file()

        # Target self-contained run folder + config.yaml + runs_index.json
        assert (target_home / "config.yaml").read_text(encoding="utf-8") == legacy_cfg.read_text(encoding="utf-8")
        index_data = json.loads((target_home / "runs_index.json").read_text(encoding="utf-8"))
        assert len(index_data["runs"]) == 1

        run_dirs = list((target_home / "runs").iterdir())
        assert len(run_dirs) == 1
        migrated_dir = run_dirs[0]
        assert (migrated_dir / "apk" / "base.apk").read_bytes() == apk_bytes
        assert (migrated_dir / "README.md").is_file()
        assert (migrated_dir / "ai_analysis" / "attempt-01" / "dossier.md").read_bytes() == dossier_bytes
        assert (migrated_dir / "ai_analysis" / "attempt-01" / "lead_ledger.json").read_bytes() == ledger_bytes
    finally:
        _make_writable_tree(source_ws)
        _make_writable_tree(target_home)


def test_pyproject_metadata_and_version_match():
    import tomllib

    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "apkworkbench"
    assert project["version"] == apkworkbench.__version__ == "0.3.0"
    assert project["license"] == "MIT"
    assert project["scripts"]["apkworkbench"] == "apkworkbench.cli.main:main"
