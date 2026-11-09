# Configuration Reference

Defaults are built into the package. Add only settings that need to change.

**Configuration:** `~/.config/apkworkbench/config.yaml`  
**Workspace:** `~/APK-Workbench-Google-Play/`

## Example

```yaml
workspace: /data/APK-Workbench-Google-Play

sources:
  google_play:
    retry_backoff_seconds: 1.0

decompilation:
  timeout_seconds: 3600

analysis:
  timeout_seconds: 7200
  max_output_bytes: 536870912

tools:
  playstore_cli: playstore-cli
  java: java
  jadx: jadx
  apktool: apktool
  trufflehog: trufflehog

logging:
  level: INFO
  file: logs/apkworkbench.log
```

## Google Play

| Key | Default | Description |
|---|---:|---|
| `sources.google_play.retry_backoff_seconds` | 1.0 | Initial delay for bounded bundle-download retries |
| `tools.playstore_cli` | `playstore-cli` | Upstream Play API package executable checked by `doctor`; local login/check-in is not required |

Discovery limits are command options rather than configuration keys:

- `discover --limit`: maximum distinct package IDs to catalogue (default 15,000).
- `discover --per-category`: top-free chart cap per category (default 200).
- `discover --per-query`: search cap per query (default 516).

The adapter uses pinned `playstore-cli==0.1.1` for the Play FDFE request, category, search, chart, and delivery protocol, plus `goopdl==2.0.0` to obtain anonymous device-session credentials from Aurora Store's public token dispenser. No local Google login, AAS token, or API key is required. The Play FDFE API still receives a short-lived bearer token internally; goopdl issues, caches, and rotates it anonymously.

The anonymous token cache defaults to `~/.config/goopdl`. Set `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` to relocate it. The adapter deliberately refuses to read `GOOPDL_ACCOUNT_EMAIL` or `GOOPDL_AAS_TOKEN`; unset those variables to remain in anonymous mode. The upstream Play API HTTP timeouts are defined by playstore-cli.

## Other tools

| Key | Default | Description |
|---|---|---|
| `decompilation.timeout_seconds` | 3600 | Maximum runtime per decompiler process |
| `analysis.timeout_seconds` | 7200 | Maximum TruffleHog runtime per APK |
| `analysis.max_output_bytes` | 536870912 | Maximum scanner output (512 MiB) |
| `tools.java` | `java` | Java executable |
| `tools.jadx` | `jadx` | JADX executable |
| `tools.apktool` | `apktool` | Apktool executable |
| `tools.trufflehog` | `trufflehog` | TruffleHog executable |
| `logging.level` | `INFO` | Python logger level |
| `logging.file` | `logs/apkworkbench.log` | Log path; relative paths resolve within the workspace |

## Environment variables

- `APKWORKBENCH_WORKSPACE`: runtime workspace root.
- `APKWORKBENCH_CONFIG_DIR`: directory containing `config.yaml`.
- `APKWORKBENCH_STATE_DIR`: application state directory.
- `GOOPDL_CONFIG_DIR`: anonymous Play token-cache directory.
- `XDG_CONFIG_HOME`: parent directory for goopdl's default token cache.

Do not place Google credentials or Play client token files in the source checkout or workspace.
