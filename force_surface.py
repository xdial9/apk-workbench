from apkworkbench.analysis.apk_surface import run_static_surface_analysis
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.core.config import Config

print("[SYSTEM] Bypassing CLI router. Initiating direct surface scan...")
ws = Config().get("workspace")
db = WorkspaceDatabase(ws)

summary = run_static_surface_analysis(
    db, ws, run_id=None, force=True, progress=print
)
print(f"[SYSTEM] Bypass complete. Processed {summary.get('completed', 0)} artifacts.")
