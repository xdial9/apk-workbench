import os
import json
import csv
import subprocess
from pathlib import Path
from apkworkbench.analysis.apk_surface import run_static_surface_analysis
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.core.config import Config

def stream_command(cmd_list):
    process = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    for line in process.stdout:
        print(line, end="")
    process.wait()
    if process.returncode != 0 and process.returncode is not None:
        raise subprocess.CalledProcessError(process.returncode, cmd_list)

def stream_trufflehog_clean(cmd_list, output_file):
    process = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    with open(output_file, 'w', encoding='utf-8') as tf:
        for line in process.stdout:
            tf.write(line)
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                detector = data.get("DetectorName", "Generic Entropy")
                source_meta = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                file_path = source_meta.get("file", "unknown_target")
                line_num = source_meta.get("line", "0")
                raw_secret = data.get("Raw", "N/A")
                print(f"[HIT] {detector:<20} | {file_path}:{line_num} | Val: {raw_secret}")
            except json.JSONDecodeError:
                if "level=info" not in line_str and "level=debug" not in line_str:
                    print(f"[LOG] {line_str}")
                    
    process.wait()

def execute_pipeline():
    print("[SYSTEM] Initializing end-to-end security analysis pipeline...")
    ws_path = Config().get("workspace")
    ws = Path(ws_path)
    db = WorkspaceDatabase(ws_path)
    
    apk_files = list(ws.glob("**/*.apk"))
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
    except Exception as e:
        print(f"[WARNING] Apktool encountered non-fatal state notice: {e}")

    # 2. LIVE STATIC SURFACE ANALYSIS
    print("\n=== STAGE: STATIC SURFACE ANALYSIS (LIVE) ===")
    surface_summary = run_static_surface_analysis(
        db, ws_path, run_id=None, force=True, progress=print
    )
    print(f"[SYSTEM] Surface analysis completed. Processed {surface_summary.get('completed', 0)} artifacts.")

    # 3. UNREDACTED TELEMETRY EXPORT
    print("\n=== STAGE: TELEMETRY & CSV EXPORT ===")
    os.makedirs("reports", exist_ok=True)
    
    for artifact in surface_summary.get("artifacts", []):
        json_path = artifact.get("path")
        if not json_path or not os.path.exists(json_path):
            continue
            
        with open(json_path, 'r', encoding='utf-8') as jf:
            data = json.load(jf)
        
        package_id = artifact.get("package_id", "com.alphainventor.filemanager")
        inventory = data.get("inventory", {})
        
        ep_file = f"reports/{package_id}_endpoints.csv"
        with open(ep_file, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(["Endpoint", "Type", "Host", "Path", "Occurrences"])
            for ep in inventory.get("endpoints", []):
                writer.writerow([
                    ep.get("value", ""), ep.get("kind", ""), 
                    ep.get("host", ""), ep.get("path", ""), ep.get("occurrences", 0)
                ])
                
        route_file = f"reports/{package_id}_routes.csv"
        with open(route_file, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(["Route_Path", "HTTP_Method", "Occurrences"])
            for r in inventory.get("api_routes", []):
                writer.writerow([
                    r.get("path", ""), r.get("http_method", "UNKNOWN"), r.get("occurrences", 0)
                ])
                    
        findings_file = f"reports/{package_id}_findings.csv"
        with open(findings_file, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(["Rule_ID", "Category", "Severity", "Confidence", "File_Path", "Line", "Snippet"])
            for f in data.get("findings", []):
                ev = f.get("evidence", {})
                writer.writerow([
                    f.get("rule_id", ""), f.get("category", ""), f.get("severity", ""),
                    f.get("confidence", ""), ev.get("path", ""), ev.get("line", ""), ev.get("snippet", "")
                ])
        print(f"[SYSTEM] Vaulted structured CSV catalogues to reports/ for {package_id}")

    # 4. LIVE TRUFFLEHOG SECRETS SCAN (CLEAN PARSED OUTPUT)
    print("\n=== STAGE: TRUFFLEHOG SECRETS SCAN (PARSED) ===")
    scan_target = decompiled_out if decompiled_out.exists() else ws
    
    truffle_output = "reports/trufflehog_findings.json"
    truffle_cmd = [
        "trufflehog",
        "filesystem",
        str(scan_target),
        "--json",
        "--no-update",
        "--only-verified"
    ]
    
    try:
        stream_trufflehog_clean(truffle_cmd, truffle_output)
        print(f"[SYSTEM] Sweep complete. Raw vault secured at {truffle_output}")
    except Exception as e:
        print(f"[WARNING] TruffleHog execution aborted: {e}")

    print("\n[SYSTEM] Pipeline execution finished. All telemetry secured.")

if __name__ == "__main__":
    execute_pipeline()
