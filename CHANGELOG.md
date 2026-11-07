# Changelog

Notable project changes are documented here. Entries under **Unreleased** describe changes on the active development branch and are not yet part of a published release.

## Unreleased

### Fixed

- Make JADX and Apktool independently resumable. A successful tool stage is skipped on ordinary retries when its published output remains present and non-empty.
- Stage each tool's output in a unique temporary sibling directory and publish it only after a zero exit code and basic output validation.
- Preserve the last published output when a tool fails, produces no files, or a forced refresh fails.
- Treat recorded tool success with a missing or empty output directory as incomplete and retry that stage.

### Documentation and tests

- Document retry semantics, staged publication, forced-refresh behavior, and current output-validation limits.
- Add regression tests for both partial-success retry paths, failed forced refreshes, and zero-exit/no-output behavior.

### Not included

- Streaming subprocess output to disk instead of buffering it in memory.
- Process-group termination and descendant cleanup on timeout.
- Memory/CPU limits or resource scheduling.
- Semantic validation of decompiled APK contents.
