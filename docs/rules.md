# Detection Rules Catalog (P5 — growth of CODE_RULES)

Source: `src/apkworkbench/analysis/apk_surface.py::CODE_RULES`.

Each entry lists: **rule_id** · **category** · **severity** · **confidence** · **what it detects** · **pattern** · **why (rationale)** · **known false-positive conditions**.

These are *review leads*, never automatic vulnerability verdicts. Every rule
cites the file:line where the pattern matched; the terminal AI decides whether
the code is actually unsafe.

---

## certificate_pinning_present
- **category:** network_security · **severity:** info · **confidence:** 0.85
- **pattern:** `CertificatePinner|setCertificatePinner|pin-set|sha256/[A-Za-z0-9+/=]{16,}`
- **detects:** A custom TLS certificate pinning control is referenced.
- **why:** A pinning control appears to be configured. Verify which hosts are
  pinned and whether every HTTP client enforces it.
- **false positives:** A pinning config that is absent or empty; host anchors
  only (e.g. a `pin-set` reference in docs with no enforcement).

## certificate_pinning_bypass
- **category:** network_security · **severity:** high · **confidence:** 0.80
- **pattern:** `setCertificatePinner\s*\(\s*null\s*\)|certificatePinner\s*=\s*null|CertificatePinner\.Builder\s*\(\s*\)\s*\.build\s*\(\s*\)`
- **detects:** A pinner is cleared or built empty.
- **why:** Confirm whether pinning is intentionally bypassed in this build
  (common in debug/flavor builds).
- **false positives:** Pinning present but intentionally disabled/built empty
  in a non-production flavor.

## keystore_credential_access
- **category:** cryptography · **severity:** medium · **confidence:** 0.80
- **pattern:** `KeyStore\.getInstance|AndroidKeyStore|Ljava/security/KeyStore;|KeyGenParameterSpec`
- **detects:** Android keystore / credential API usage.
- **why:** Key material is handled through a keystore API. Review key
  protection flags, user-authentication binding and export paths.
- **false positives:** None commonly observed; every keystore use warrants review.

## sql_string_concatenation
- **category:** data_storage · **severity:** high · **confidence:** 0.78
- **pattern:** `(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;\n]{0,160}["']\s*\+|\+\s*["'][^"'\n]{0,60}(?:WHERE|FROM|VALUES|ORDER\s+BY|LIMIT)\b|String\.format\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)`
- **detects:** A SQL statement is assembled from literal and non-literal parts.
- **why:** Check whether untrusted input reaches the concatenated segment
  instead of a bound parameter.
- **false positives:** Static SQL where every concatenated segment is a
  compile-time constant (no untrusted input); string building for non-SQL
  queries that happen to contain SQL keywords.

## path_traversal
- **category:** file_system · **severity:** medium · **confidence:** 0.70
- **pattern:** `["'][^"'\n]*\.\./(?:\.\./)*|%2e%2e%2f`
- **detects:** A relative parent-directory path component in a string literal.
- **why:** Confirm whether it is joined with untrusted input and whether
  canonicalization or an allow-list bounds the result.
- **false positives:** Intentional relative paths to known safe subfolders
  (e.g. `"../res/raw/config.json"`); percent-encoded `%2e` in URL handling
  that is not a filesystem path.

## intent_redirection
- **category:** components · **severity:** medium · **confidence:** 0.70
- **pattern:** `Landroid/content/Intent;->getParcelableExtra|getParcelableExtra\s*\(|getParcelableArrayListExtra\s*\(`
- **detects:** A Parcelable extra is read from an Intent.
- **why:** If that Parcelable is itself an Intent and is started/forwarded
  without validation, an external caller can redirect it to a protected
  component.
- **false positives:** Reading non-Intent Parcelable extras (e.g. a custom
  serializable config object) with no subsequent `startActivity`.

## overlay_window
- **category:** components · **severity:** high · **confidence:** 0.85
- **pattern:** `TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|SYSTEM_ALERT_WINDOW`
- **detects:** An overlay window type or the SYSTEM_ALERT_WINDOW permission.
- **why:** Review whether the overlay can sit above other apps and what it
  displays (potential tapjacking / phishing surface).
- **false positives:** Legitimate accessibility or AR overlays that declare
  `TYPE_APPLICATION_OVERLAY` for their own UI and are user-initiated.

## clipboard_access
- **category:** privacy · **severity:** medium · **confidence:** 0.80
- **pattern:** `ClipboardManager|getPrimaryClip|setPrimaryClip|Landroid/content/ClipboardManager;`
- **detects:** Clipboard read/write API usage.
- **why:** Check whether sensitive data can be captured from, or leaked to,
  the clipboard (e.g. password managers, OTP copying).
- **false positives:** Legitimate copy/paste functionality that the user
  explicitly triggers.

## accessibility_service
- **category:** components · **severity:** high · **confidence:** 0.85
- **pattern:** `AccessibilityService|BIND_ACCESSIBILITY_SERVICE|Landroid/accessibilityservice/AccessibilityService;`
- **detects:** An accessibility service surface.
- **why:** An accessibility service can observe and act on other apps' UI.
  Verify the service is declared, intended and restricted
  (`android:exported="false"`, `android:permission`).
- **false positives:** Legitimate accessibility services (screen readers,
  switch access) that bind with `android:exported="false"`.

## root_emulator_detection
- **category:** environment_checks · **severity:** info · **confidence:** 0.80
- **pattern:** `Superuser\.apk|/system/xbin/su|/system/bin/su\b|test-keys|ro\.debuggable|ro\.kernel\.qemu|ro\.hardware\.goldfish|genymotion`
- **detects:** Root/emulator detection indicators.
- **why:** This is defensive-posture evidence, not a vulnerability. Note which
  checks run and what the app does when they fire (block, warn, allow).
- **false positives:** Debug/test builds that include these markers; apps that
  detect root only to show a warning.

## exported_provider_risk
- **category:** components · **severity:** high · **confidence:** 0.80
- **pattern:** `Landroid/content/ContentResolver;->query\(|->insert\(Landroid/net/Uri;|->bulkInsert\(|->update\(Landroid/net/Uri;`
- **detects:** Code invokes ContentResolver query/insert/bulkInsert/update with
  a `content://` URI.
- **why:** Pair this with the manifest's exported `<provider>` facts
  (`exported_component`) to determine whether any app that can reach the
  authority may query or insert. Review `readPermission` / `writePermission`,
  `grantUriPermissions` and path restrictions.
- **false positives:** Apps that query their own provider internally with no
  exported provider; content URIs that are not backed by a provider.

## task_hijacking
- **category:** components · **severity:** medium · **confidence:** 0.75
- **pattern:** `android:taskAffinity\s*=\s*"[^"]+"|android:launchMode\s*=\s*"(?:singleTask|singleInstance)\"`
- **detects:** An activity sets `taskAffinity` or a
  `singleTask` / `singleInstance` launch mode.
- **why:** An attacker activity with the same affinity can hijack the task.
  Verify the affinity matches the package name and that the launch mode is
  actually required.
- **false positives:** Apps that use a singleton task for internal work
  (e.g. a login activity) with the default package-name affinity.

---

## Notes

- These are review leads, never automatic vulnerability verdicts.
- Every rule cites the file:line where the pattern matched; the terminal AI
  decides whether the code is actually unsafe.
- The docs do NOT list every possible benign pattern; the test suite includes
  negative fixtures that cover the most common edge cases.
- This catalog is kept in sync with `CODE_RULES` in
  `src/apkworkbench/analysis/apk_surface.py`.