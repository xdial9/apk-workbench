# Retry-safe Apktool decoding

## Purpose

The active workbench pipeline uses one decompiler for each acquired APK component: Apktool. JADX is not invoked by the current runner or TruffleHog scan stage.

## Normal retry behavior

The runner reuses an Apktool result only when both conditions hold:

1. The processing database records `apktool_status=success`.
2. The `apktool/` output directory exists, is a real directory rather than a symlink, and contains at least one regular file.

When both conditions hold, the artifact is skipped unless `--force` is supplied. A recorded success with a missing or empty output directory is not trusted; Apktool is invoked again.

The legacy `jadx_status` CSV column remains in the workspace schema so existing processing databases continue to load. New runs set this field to `not_used`. Historical JADX status values are ignored by the Apktool runner, TruffleHog eligibility check and run reconciliation.

## Staged output publication

Apktool writes to a unique staging directory beside the final `apktool/` output. The existing published output is retained until the new process exits successfully and the staged directory contains usable files. Publication then replaces the prior directory.

If the process exits nonzero, times out, is interrupted or produces no usable output, the staging directory is removed and a previously successful `apktool/` directory remains untouched. A failed forced refresh is reported as requiring attention without destroying the previous result.

## Files

For an artifact at `results/<package>/<version>/<sha256>/`:

- `apktool/` — decoded manifest, resources and Smali output.
- `apktool.log` — combined Apktool stdout/stderr and process exit status.
- `.apktool.staging-<random-id>/` — transient staged output, removed after completion or failure cleanup.

Historical `jadx/` directories and logs are not deleted. They are not read or scanned by the current pipeline.

## Input and process integrity

Before invoking Apktool, the runner validates that the acquired APK is a regular non-symlink file inside the configured `downloads/` workspace and independently verifies its recorded size and SHA-256 digest.

Output roots, staging paths and log targets are checked against symlink and workspace-escape conditions. The runner retains bounded process execution, streamed logs, process-group termination on timeout or interruption, transactional output publication and retry semantics.
