![APK WORKBENCH](docs/assets/apk-workbench-banner.svg)

# Security Policy

APK WORKBENCH processes third-party Android packages and generated decompiler output. Treat both as untrusted input.

## Supported versions

Security reports are accepted for the current default branch, **main**.

## Reporting a vulnerability

Do not publish an unpatched vulnerability, exploit details, credentials, private APK contents, or personal data in a public issue.

Use GitHub's **Report a vulnerability** flow from the repository Security tab when private vulnerability reporting is available. If it is unavailable, contact the repository owner through the GitHub profile and request a private reporting channel.

Include:

- Affected commit or release.
- Affected component and relevant configuration.
- Concise reproduction steps.
- Impact and realistic prerequisites.
- Suggested mitigation, if known.

Use synthetic data and redact secrets. Do not include active credentials or sensitive APK contents.

## Security design

The application is designed to:

- Retrieve the F-Droid repository index over HTTPS.
- Verify the detached OpenPGP signature against a pinned primary fingerprint before parsing index content.
- Enforce response-size and request-time limits.
- Verify downloaded APK byte count and SHA-256 before publishing an artifact.
- Record acquisition in append-only history and immutable run manifests.
- Re-check APK integrity before decompilation.
- Use sequential external subprocess execution with timeouts.
- Run TruffleHog with credential verification disabled.
- Persist sanitized finding metadata and one-way fingerprints rather than raw secret values.
- Reject paths that escape managed workspace boundaries.

These controls reduce defined risks; they do not prove that an APK is safe or benign.

## Safe handling

APK WORKBENCH performs static analysis. It does not install or execute acquired APKs. Do not manually install or launch untrusted APKs as part of a static-analysis workflow.

Run the application with least privilege, keep the operating system and external tools patched, and treat APKs, decompiler output, and scanner output as untrusted data.

Scanner findings are unverified candidate indicators. They are not proof that a credential is active, valid, or exploitable.
