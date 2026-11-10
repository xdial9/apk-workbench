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
| `tools.playstore_cli` | `playstore-cli` | Upstream login/check-in executable |

Discovery limits are command options rather than configuration keys:

- `discover --limit`: maximum distinct package IDs to catalogue (default 15,000).
- `discover --per-category`: top-free chart cap per category (default 200).
- `discover --per-query`: search cap per query (default 516).

The adapter uses the pinned `playstore-cli==0.1.1` Python package directly for Play API/session/download operations. The upstream HTTP timeouts are defined by that package.

Authenticate in the same Python environment as APK Workbench:

```bash
playstore-cli login
playstore-cli checkin
```

The adapter reads the upstream client's local account, device, and session files. By default those are stored under `~/.config/playstore-cli`; the upstream `PLAYSTORE_HOME` environment variable can relocate them. These files contain a long-lived authentication token and must remain private.

## Other tools

Apktool is the sole active decompiler. JADX is no longer an installed runtime dependency or a required configuration key. The legacy `jadx_status` processing column remains for existing workspace compatibility.


| Key | Default | Description |
|---|---|---|
| `decompilation.timeout_seconds` | 3600 | Maximum runtime per Apktool process |
| `analysis.timeout_seconds` | 7200 | Maximum TruffleHog runtime per APK |
| `analysis.max_output_bytes` | 536870912 | Maximum scanner output (512 MiB) |
| `tools.java` | `java` | Java executable |
| `tools.apktool` | `apktool` | Apktool executable |
| `tools.trufflehog` | `trufflehog` | TruffleHog executable |
| `logging.level` | `INFO` | Python logger level |
| `logging.file` | `logs/apkworkbench.log` | Log path; relative paths resolve within the workspace |

## Environment variables

- `APKWORKBENCH_WORKSPACE`: runtime workspace root.
- `APKWORKBENCH_CONFIG_DIR`: directory containing `config.yaml`.
- `APKWORKBENCH_STATE_DIR`: application state directory.
- `PLAYSTORE_HOME`: upstream Play client credential/session directory.

Do not place Google credentials or Play client token files in the source checkout or workspace.
