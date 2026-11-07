![APK WORKBENCH](assets/apk-workbench-banner.svg)

# Configuration Reference

APK WORKBENCH uses explicit YAML overrides. Defaults are built into the Python package; add only settings that need to change.

**Configuration file:** ~/.config/apkworkbench/config.yaml  
**Default runtime workspace:** ~/APK-Workbench/

---

## Complete configuration example

~~~yaml
workspace: /data/APK-Workbench

gpg:
  executable: gpg
  homedir: ~/.local/state/apkworkbench/gpg
  trusted_fingerprints:
    - 37D2C98789D8311948394E3E41E7044E1DBA2E89
  timeout_seconds: 30

sources:
  fdroid:
    repository_url: https://f-droid.org/repo
    key_url: https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x37D2C98789D8311948394E3E41E7044E1DBA2E89
    signer_fingerprint: 37D2C98789D8311948394E3E41E7044E1DBA2E89
    timeout_seconds: 30
    max_index_bytes: 134217728
    max_signature_bytes: 1048576
    max_key_bytes: 2097152
    download_timeout_seconds: 60

decompilation:
  timeout_seconds: 3600

analysis:
  timeout_seconds: 7200
  max_output_bytes: 536870912

tools:
  gpg: gpg
  java: java
  jadx: jadx
  apktool: apktool
  trufflehog: trufflehog

logging:
  level: INFO
  file: logs/apkworkbench.log
~~~

## Setting reference

### Workspace

| Key | Default | Description |
|---|---|---|
| **workspace** | ~/APK-Workbench | Runtime root for downloads, manifests, records, results, reports, and logs |

Use a filesystem with sufficient free space for original APKs and generated decompilations. JADX and Apktool output can be substantially larger than the input APK.

### GnuPG

| Key | Default | Description |
|---|---|---|
| **gpg.executable** | gpg | GnuPG executable |
| **gpg.homedir** | ~/.local/state/apkworkbench/gpg | Isolated application GPG home |
| **gpg.trusted_fingerprints** | F-Droid primary fingerprint | Explicit primary-key allowlist |
| **gpg.timeout_seconds** | 30 | Timeout for each GPG operation |

Default F-Droid primary fingerprint:

~~~text
37D2C98789D8311948394E3E41E7044E1DBA2E89
~~~

The application's GPG home is separate from the user's personal keyring.

### F-Droid source

| Key | Default | Description |
|---|---|---|
| **sources.fdroid.repository_url** | https://f-droid.org/repo | APK repository base URL |
| **sources.fdroid.key_url** | Ubuntu keyserver URL for the pinned key | Public-key retrieval endpoint; not a trust anchor |
| **sources.fdroid.signer_fingerprint** | F-Droid primary fingerprint | Required primary fingerprint for signature verification |
| **sources.fdroid.timeout_seconds** | 30 | HTTP request timeout |
| **sources.fdroid.max_index_bytes** | 134217728 | Maximum index response size (128 MiB) |
| **sources.fdroid.max_signature_bytes** | 1048576 | Maximum signature response size (1 MiB) |
| **sources.fdroid.max_key_bytes** | 2097152 | Maximum key response size (2 MiB) |
| **sources.fdroid.download_timeout_seconds** | 60 | Timeout for an APK download |

The HTTP client requires HTTPS, rejects redirects, and enforces response-size limits. The pinned fingerprint—not the keyserver URL—defines the expected signing identity.

### Decompilation

| Key | Default | Description |
|---|---:|---|
| **decompilation.timeout_seconds** | 3600 | Maximum execution time per decompiler process |

### Static analysis

| Key | Default | Description |
|---|---:|---|
| **analysis.timeout_seconds** | 7200 | Maximum TruffleHog execution time per APK |
| **analysis.max_output_bytes** | 536870912 | Maximum captured scanner output (512 MiB) |

TruffleHog runs with credential verification disabled. Do not weaken that behavior or its CLI capability checks.

### External executables

| Key | Default |
|---|---|
| **tools.gpg** | gpg |
| **tools.java** | java |
| **tools.jadx** | jadx |
| **tools.apktool** | apktool |
| **tools.trufflehog** | trufflehog |

Use an absolute path when an executable is not available through the process PATH.

### Logging

| Key | Default | Description |
|---|---|---|
| **logging.level** | INFO | Python logger level |
| **logging.file** | logs/apkworkbench.log | Log path; relative paths are resolved within the workspace |

---

## Environment variables

Environment variables override directory defaults:

| Variable | Purpose |
|---|---|
| **APKWORKBENCH_WORKSPACE** | Runtime workspace root |
| **APKWORKBENCH_CONFIG_DIR** | Directory containing config.yaml |
| **APKWORKBENCH_STATE_DIR** | Application state directory, including isolated GPG state |

Example:

~~~bash
export APKWORKBENCH_WORKSPACE="/mnt/data/APK-Workbench"
export APKWORKBENCH_CONFIG_DIR="$HOME/.config/apkworkbench"
export APKWORKBENCH_STATE_DIR="$HOME/.local/state/apkworkbench"
~~~

Add the exports to your shell profile if they should persist across terminal sessions.

## Trust-pin changes

The default GPG primary fingerprint is a security trust anchor. Do not change it merely to resolve an index verification error.

Before changing it:

1. Confirm the replacement fingerprint against an independent F-Droid-published source.
2. Update the **gpg.trusted_fingerprints** allowlist.
3. Update **sources.fdroid.signer_fingerprint**.
4. Run authenticated discovery and inspect the verification output.

The key retrieval URL is only a transport location. The application imports the retrieved key, checks its primary fingerprint, and verifies the detached index signature against that identity.

## Storage and backup

Back up the runtime workspace when acquisition history, frozen manifests, decompilations, or reports must be retained. The source checkout can be recloned; the workspace contains the operational record.

Do not place real APKs, generated source, findings, or logs in the Git repository.
