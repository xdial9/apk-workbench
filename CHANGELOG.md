# Changelog

Notable project changes are documented here. Entries under **Unreleased** describe changes on the active development branch and are not yet part of a published release.

## Unreleased

### Added

- Stream combined JADX and Apktool output directly to per-artifact logs, avoiding unbounded in-memory subprocess capture.
- Terminate decompiler and TruffleHog process groups on timeout, SIGTERM, or interruption.
- Add bounded acquisition retries for transient connection failures and retryable HTTP statuses, honoring `Retry-After`.
- Serialize workspace reads, mutations, and complete CLI jobs with a re-entrant interprocess lock.
- Reconcile every frozen acquisition-manifest entry into an explicit terminal or unresolved outcome at pipeline completion.
- Add `apkworkbench reconcile --run-id <run-id>` to inspect an interrupted or incomplete run.
- Add a real-subprocess integration test using synthetic JADX, Apktool, and TruffleHog executables.

### Fixed

- Preserve the last published output when a decompiler fails, produces no files, or a forced refresh fails.
- Treat verified APKs whose acquisition-history record cannot be committed as fatal workspace persistence errors.
- Account for malformed acquisition-history records rather than silently skipping them.
- Reject symlinked APK inputs, decompilation paths, scan inputs, report inputs, and report output components.
- Reject empty decompilation directories as TruffleHog scan inputs.
- Preserve bounded TruffleHog stderr diagnostics rather than discarding them.
- Correct the streaming subprocess tests so they mock the actual `subprocess.Popen` implementation.

### Documentation and tests

- Document retry semantics, staged publication, workspace locking, per-run reconciliation, and recovery commands.
- Add regression coverage for timeout cleanup, output rollback, retry behavior, concurrent database writers, malformed records, and path-symlink defenses.
- Validate the test suite on Python 3.10, 3.11, and 3.12, with Ruff on Python 3.11.

### Remaining limitations

- A representative real APK batch and sustained overnight soak test have not yet been run.
- Resource scheduling/quotas and semantic validation of decompiled APK contents remain outside this reliability patch.
