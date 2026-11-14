# Configuration Reference

Defaults are built into the package. Add only settings that need to change.

**Configuration:** `~/.config/apkworkbench/config.yaml`  
**Workspace:** `~/APK-Workbench/workspace/`

## Example

```yaml
workspace: /data/APK-Workbench/workspace

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
| `tools.playstore_cli` | `playstore-cli` | Google Play API/delivery client executable checked by `doctor`; local account login is not used |

Discovery limits are command options rather than configuration keys:

- `discover --limit`: maximum distinct package IDs to catalogue (default 15,000).
- `discover --per-category`: top-free chart cap per category (default 200).
- `discover --per-query`: search cap per query (default 516).

The adapter uses pinned `playstore-cli==0.1.1` for Google's Play API and bundle delivery protocol, plus `goopdl==2.0.0` for anonymous device-session credentials from Aurora Store's public token dispenser. The Play API still receives a short-lived bearer token, but the token is issued anonymously; no Google account, AAS token, or API key is needed. goopdl rotates rejected tokens and keeps its private token pool outside the source checkout.

No `playstore-cli login` or `playstore-cli checkin` step is used. The anonymous token cache defaults to `~/.config/goopdl`; `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` can relocate it. On POSIX, goopdl creates the cache directory with mode `0700` and token files with mode `0600`. The adapter fails closed when `GOOPDL_ACCOUNT_EMAIL` or `GOOPDL_AAS_TOKEN` is set; unset both to use anonymous mode.

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
- `GOOPDL_CONFIG_DIR`: optional directory for the anonymous goopdl token cache.
- `XDG_CONFIG_HOME`: goopdl uses `$XDG_CONFIG_HOME/goopdl` when set and no explicit `GOOPDL_CONFIG_DIR` is provided.
- `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN`: not supported by APK Workbench's Play adapter; if either is set, anonymous access is stopped rather than falling back to account credentials.

Do not place Google credentials or anonymous Play token files in the source checkout or workspace.
