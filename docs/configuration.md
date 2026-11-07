# Configuration

APK WORKBENCH loads optional YAML overrides from:

```text
~/.config/apkworkbench/config.yaml
```

The default settings are supplied by the package. Only override values that need changing.

Example:

```yaml
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
```

## Trust pin changes

The default GPG primary fingerprint is an explicit trust pin. Do not change it merely to make an index verification error disappear. Confirm any replacement fingerprint against an independent F-Droid-published trust source, then update both the allowlist and the F-Droid source's `signer_fingerprint`.

The public-key retrieval URL is not itself the trust anchor. GPG import must yield the expected primary fingerprint, and detached-signature verification must report a valid signature from that pinned primary key.

## Environment overrides

These environment variables override directory defaults:

- `APKWORKBENCH_WORKSPACE`
- `APKWORKBENCH_CONFIG_DIR`
- `APKWORKBENCH_STATE_DIR`

The workspace should be on a filesystem with enough space for original APKs and their full decompilations. JADX and Apktool outputs can be substantially larger than the APK itself.
