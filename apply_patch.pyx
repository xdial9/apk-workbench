p = "src/apkworkbench/analysis/apk_surface.py"
s = open(p).read()

def rep(old, new):
    global s
    assert s.count(old) == 1, ("NO MATCH, nothing written", old[:60])
    s = s.replace(old, new)

rep("import tempfile\nimport xml", "import tempfile\nimport time\nimport xml")

rep('def analyze_apk_surface(apktool_dir: str | Path) -> dict[str, Any]:\n',
    'def analyze_apk_surface(\n    apktool_dir: str | Path,\n    *,\n    progress: Callable[[str], None] | None = None,\n) -> dict[str, Any]:\n')

rep("""    scanned_text_bytes = 0
    code_scanned = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
""", """    scanned_text_bytes = 0
    code_scanned = 0
    scannable_total = sum(1 for item in files if item.suffix.lower() in TEXT_SUFFIXES)
    scan_started = last_heartbeat = time.monotonic()
    files_seen = 0
    _emit_progress(
        progress,
        f"[Surface] Scanning {scannable_total:,} text files ({len(smali_files):,} smali) for endpoints, routes and indicators",
    )
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        files_seen += 1
        if time.monotonic() - last_heartbeat >= 10:
            last_heartbeat = time.monotonic()
            _emit_progress(
                progress,
                f"[Surface] still scanning - {files_seen:,}/{scannable_total:,} files, "
                f"{int(last_heartbeat - scan_started)}s elapsed, "
                f"{len(api_endpoints):,} endpoints, {len(findings):,} findings",
            )
""")

rep("            result = analyze_apk_surface(decoded)\n",
    "            result = analyze_apk_surface(decoded, progress=progress)\n")

open(p, "w").write(s)
print("PATCHED OK")
