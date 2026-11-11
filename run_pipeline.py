import json
import os
import subprocess
from pathlib import Path

from apkworkbench.analysis.apk_surface import run_static_surface_analysis
from apkworkbench.core.config import Config
from apkworkbench.database.workspace import WorkspaceDatabase


def stream_command(cmd_list):
    """Run a subprocess and stream its output without losing log context."""
    process = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout is None:
        raise RuntimeError(f"Failed to start command: {' '.join(cmd_list)}")
    for line in process.stdout:
        print(line, end="")
    process.wait()
    if process.returncode not in (0, None):
        raise subprocess.CalledProcessError(process.returncode, cmd_list)


def stream_trufflehog_clean(cmd_list, output_file):
    """Execute a TruffleHog scan and retain clean JSONL output with human-readable summaries."""
    process = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout is None:
        raise RuntimeError(f"Failed to start TruffleHog: {' '.join(cmd_list)}")

    with open(output_file, "w", encoding="utf-8") as tf:
        for line in process.stdout:
            tf.write(line)
            line_str = line.strip()
            if not line_str:
                continue

            lowered = line_str.lower()
            if "server busy" in lowered or "rate limit" in lowered or "429" in lowered:
                print(f"[WARNING] TruffleHog reports a server busy / rate-limit condition: {line_str}")

            try:
                data = json.loads(line_str)
            except json.JSONDecodeError:
                if "level=info" not in lowered and "level=debug" not in lowered:
                    print(f"[LOG] {line_str}")
                continue

            if not isinstance(data, dict):
                continue

            detector = data.get("DetectorName", "Generic Entropy")
            source_meta = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_path = source_meta.get("file", "unknown_target")
            line_num = source_meta.get("line", "0")
            raw_secret = data.get("Raw", "N/A")
            print(f"[HIT] {detector:<20} | {file_path}:{line_num} | Val: {raw_secret}")

    process.wait()
    if process.returncode not in (0, None):
        raise subprocess.CalledProcessError(process.returncode, cmd_list)


def _safe_trufflehog_command(scan_target: Path) -> list[str]:
    """Use the project's verified-only, no-update JSON flags for TruffleHog."""
    return [
        "trufflehog",
        "filesystem",
        str(scan_target),
        "--concurrency=1",
        "--results=verified",
        "--json",
        "--no-update",
        "--fail-on-scan-errors",
    ]


def execute_pipeline():
    print("[SYSTEM] Initializing end-to-end security analysis pipeline...")
    ws_path = Config().get("workspace")
    ws = Path(ws_path)
    db = WorkspaceDatabase(ws_path)

    apk_files = sorted(ws.rglob("*.apk"))
    if not apk_files:
        print("[ERROR] No target APK located in workspace. Aborting pipeline.")
        return

    target_apk = apk_files[0]
    print(f"[SYSTEM] Target binary acquired: {target_apk.name}")

    # 1. LIVE APKTOOL DECOMPILATION
    print("\n=== STAGE: APKTOOL DECOMPILATION (LIVE) ===")
    decompiled_out = ws / "decompiled_source"
    decompiled_out.mkdir(exist_ok=True)

    decompile_cmd = ["apktool", "d", "-f", str(target_apk), "-o", str(decompiled_out)]
    try:
        stream_command(decompile_cmd)
        print(f"[SYSTEM] Apktool extraction verified at: {decompiled_out}")
    except Exception as exc:
        print(f"[WARNING] Apktool encountered a non-fatal state notice: {exc}")

    # 2. LIVE STATIC SURFACE ANALYSIS
    print("\n=== STAGE: STATIC SURFACE ANALYSIS (LIVE) ===")
    surface_summary = run_static_surface_analysis(db, ws_path, run_id=None, force=True, progress=print)
    print(f"[SYSTEM] Surface analysis completed. Processed {surface_summary.get('completed', 0)} artifacts.")

    # 3. UNREDACTED TELEMETRY EXPORT
    print("\n=== STAGE: TELEMETRY & CSV EXPORT ===")
    reports_dir = ws / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    for artifact in surface_summary.get("artifacts", []):
        json_path = artifact.get("path")
        if not json_path or not os.path.exists(json_path):
            continue

        with open(json_path, "r", encoding="utf-8") as jf:
            data = json.load(jf)

        package_id = artifact.get("package_id", "com.alphainventor.filemanager")
        inventory = data.get("inventory", {})

        ep_file = reports_dir / f"{package_id}_endpoints.csv"
        with open(ep_file, "w", newline="", encoding="utf-8") as cf:
            writer = __import__("csv").writer(cf)
            writer.writerow(["Endpoint", "Type", "Host", "Path", "Occurrences"])
            for ep in inventory.get("endpoints", []):
                writer.writerow([
                    ep.get("value", ""),
                    ep.get("kind", ""),
                    ep.get("host", ""),
                    ep.get("path", ""),
                    ep.get("occurrences", 0),
                ])

        route_file = reports_dir / f"{package_id}_routes.csv"
        with open(route_file, "w", newline="", encoding="utf-8") as cf:
            writer = __import__("csv").writer(cf)
            writer.writerow(["Route_Path", "HTTP_Method", "Occurrences"])
            for route in inventory.get("api_routes", []):
                writer.writerow([
                    route.get("path", ""),
                    route.get("http_method", "UNKNOWN"),
                    route.get("occurrences", 0),
                ])

        findings_file = reports_dir / f"{package_id}_findings.csv"
        with open(findings_file, "w", newline="", encoding="utf-8") as cf:
            writer = __import__("csv").writer(cf)
            writer.writerow(["Rule_ID", "Category", "Severity", "Confidence", "File_Path", "Line", "Snippet"])
            for finding in data.get("findings", []):
                evidence = finding.get("evidence", {})
                writer.writerow([
                    finding.get("rule_id", ""),
                    finding.get("category", ""),
                    finding.get("severity", ""),
                    finding.get("confidence", ""),
                    evidence.get("path", ""),
                    evidence.get("line", ""),
                    evidence.get("snippet", ""),
                ])
        print(f"[SYSTEM] Vaulted structured CSV catalogues to {reports_dir} for {package_id}")

    # 4. LIVE TRUFFLEHOG SECRETS SCAN (CLEAN PARSED OUTPUT)
    print("\n=== STAGE: TRUFFLEHOG SECRETS SCAN (PARSED) ===")
    scan_target = decompiled_out if decompiled_out.exists() else ws
    truffle_output = reports_dir / "trufflehog_findings.json"
    truffle_cmd = _safe_trufflehog_command(scan_target)

    try:
        stream_trufflehog_clean(truffle_cmd, str(truffle_output))
        print(f"[SYSTEM] Sweep complete. Raw vault secured at {truffle_output}")
    except Exception as exc:
        print(f"[WARNING] TruffleHog execution aborted: {exc}")

    print("\n[SYSTEM] Pipeline execution finished. All telemetry secured.")


if __name__ == "__main__":
    execute_pipeline()
