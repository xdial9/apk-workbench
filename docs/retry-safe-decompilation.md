# Retry-safe decompilation

## Purpose

JADX and Apktool are independent stages for each acquired APK. A failure in one stage must not erase or unnecessarily repeat a successful result from the other stage.

## Normal retry behavior

The runner reuses a tool result only when both conditions hold:

1. The processing database records that tool's status as `success`.
2. The corresponding output directory exists, is a real directory rather than a symlink, and contains at least one regular file.

When both tools satisfy those checks, the artifact is skipped. When only one does, the runner invokes only the other tool. A recorded success with a missing or empty output directory is not trusted; that tool is attempted again.

This makes the two partial states resumable:

| Existing state | Next normal attempt |
|---|---|
| JADX succeeded; Apktool failed | Keep JADX output; retry Apktool only |
| Apktool succeeded; JADX failed | Keep Apktool output; retry JADX only |
| Both succeeded and both outputs contain files | Skip the artifact |
| Status says success but output is missing/empty | Retry that tool |
| Neither tool succeeded | Attempt both sequentially |

## Staged output publication

A tool never writes directly over its published output. Each invocation receives a unique temporary sibling directory under the APK's result directory.

After the tool exits with code zero, the runner verifies that the staging directory contains at least one regular file. Only then does it move the previous published output to a uniquely named backup and atomically move the staged output into place.

If the tool fails, exits successfully without producing files, or publication fails, the existing published output is retained. If publication fails after the old output has been moved aside, the runner attempts to restore it. A backup is retained and its path reported if rollback itself fails.

Temporary staging output is removed after a failed attempt where possible. A backup that cannot be cleaned after a successful publication is logged as a warning; the new output remains published.

## Forced retries

`apkworkbench decompile --force` intentionally invokes both tools again, even if their current outputs are usable.

Forced runs use the same staging and publication process. A failed forced refresh does not invalidate the previously successful output or its `success` status. The command still reports the failed refresh and exits non-zero, so the failure is visible without discarding the last known-good result.

## Logs and status

JADX and Apktool retain separate logs:

- `<artifact result directory>/jadx.log`
- `<artifact result directory>/apktool.log`

The processing status represents the last known usable published output for each tool. A failed forced refresh can therefore leave a tool marked `success` while the error field records the unsuccessful refresh; inspect the tool log and command summary when a forced run reports a failure.

The output check is deliberately a basic integrity check (a real directory containing at least one regular file). It does not parse JADX source trees or validate Apktool's decoded manifest/resources semantically.

## Regression coverage

The decompilation test suite covers:

- retrying Apktool without repeating a successful JADX stage;
- retrying JADX without repeating a successful Apktool stage;
- retaining the last successful output after a failed forced refresh;
- refusing to record success when a tool exits zero but creates no output;
- continuing to enforce the frozen manifest scope and APK digest verification.

The separate subprocess streaming, process-group timeout, and memory-control improvements remain out of scope for this retry-safety change.
