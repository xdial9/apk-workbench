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

The catalog itself is a rolling union: every discover session merges its result into `database/google_play_discovery.csv` after each completed query/category channel, and reruns only ever add package IDs. A rate-limit abort partway through a category crawl keeps the progress made so far.

## Play authentication (`sources.google_play.auth_mode`)

| Key | Default | Values |
|---|---|---|
| `sources.google_play.auth_mode` | `auto` | `auto`, `account`, `anonymous` |

The adapter uses pinned `playstore-cli==0.1.1` for Google's Play API and bundle delivery protocol, plus `goopdl==2.0.0` for Play device-session credentials. The Play API still receives a short-lived bearer token internally; the mode decides where it comes from:

- **`account`** — your own Google account (recommended; the Aurora dispenser is never contacted). Credentials resolve from, in order: `GOOPDL_ACCOUNT_EMAIL` + `GOOPDL_AAS_TOKEN`, then the account saved with `goopdl auth login` (system keyring, else `~/.config/goopdl/account.json`). Without any of these, commands fail fast with instructions instead of guessing.
- **`anonymous`** — Aurora Store's public token dispenser only. This is a third-party service that is frequently unavailable or rate-limited. Fails closed when account environment variables are present: in this mode they are not read or used.
- **`auto`** (default) — account mode when credentials resolve; anonymous otherwise.

goopdl rotates rejected tokens in every mode; after a Play 401 it re-mints the bearer, and a second consecutive rejection retires and re-registers the device. When a token source advertises a `retry_after` window (for example a dispenser 429), the adapter honors it with a capped sleep before re-minting.

`apkworkbench doctor` reports which session source will be used (masked email included). The goopdl cache defaults to `~/.config/goopdl`; `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` can relocate it. On POSIX, goopdl creates the cache directory with mode `0700` and token files with mode `0600`.

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
- `GOOPDL_CONFIG_DIR`: optional directory for the goopdl token/device cache.
- `XDG_CONFIG_HOME`: goopdl uses `$XDG_CONFIG_HOME/goopdl` when set and no explicit `GOOPDL_CONFIG_DIR` is provided.
- `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN`: optional account credentials enabling account-mode Play sessions. They are used in `auth_mode=account` or `auto`; in `anonymous` mode the adapter fails closed instead of reading them. Read the email/token pair from `goopdl auth login --print` if you prefer the environment over the saved account.

Do not place Google credentials or anonymous Play token files in the source checkout or workspace.
