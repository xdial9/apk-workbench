# Security Policy

## Supported scope

Security reports are welcome for the current default branch of APK WORKBENCH.

## Reporting a vulnerability

Please do not publish an unpatched vulnerability, exploit details, credentials, or sensitive APK contents in a public issue.

Use GitHub's **Report a vulnerability** flow on the repository's Security tab if private vulnerability reporting is enabled. If that option is unavailable, contact the repository owner through their GitHub profile and request a private channel for responsible disclosure.

Include:

- affected commit or release;
- affected component and configuration;
- concise reproduction steps;
- impact and realistic attack prerequisites;
- suggested mitigation, if known.

Do not include live secrets or personal data in a report. Redact values and use synthetic examples.

## Security design notes

APK WORKBENCH is designed to:

- authenticate the F-Droid repository index before parsing it;
- pin the expected OpenPGP primary fingerprint;
- verify downloaded APK size and SHA-256 before publication;
- re-check artifact integrity before decompilation;
- keep subprocess execution sequential;
- disable TruffleHog credential verification;
- persist sanitized findings rather than raw secret values;
- reject filesystem paths that escape managed workspace boundaries.

These controls reduce specific risks; they do not make untrusted APKs safe to execute. APK WORKBENCH performs static analysis and does not install or run acquired APKs. Treat APKs and decompiler output as untrusted input, keep the host patched, and run analysis with least privilege.
