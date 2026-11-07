![APK WORKBENCH](assets/apk-workbench-banner.svg)

# F-Droid Source Verification

**Scope:** authenticated F-Droid discovery and APK acquisition  
**Repository:** https://f-droid.org/repo  
**Index format:** index-v2.json with detached OpenPGP signature

This document records the source-selection and trust decisions implemented by APK WORKBENCH.

## 01 · Acquisition source

APK WORKBENCH uses the signed repository index as the source of truth for acquisition decisions. The per-app API is not used as the download or verification authority.

The current adapter retrieves the full index and detached signature:

~~~text
https://f-droid.org/repo/index-v2.json
https://f-droid.org/repo/index-v2.json.asc
~~~

The F-Droid entry point and archive endpoints are documented below for future incremental-index or archive-source support. They are not silently substituted for the configured main repository.

## 02 · OpenPGP trust anchor

The configured primary fingerprint for F-Droid <admin@f-droid.org> is:

~~~text
37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89
~~~

The documented signing subkey fingerprint is:

~~~text
802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A
~~~

The primary fingerprint is the trust anchor. When GnuPG reports a signing subkey in its machine-readable **[GNUPG:] VALIDSIG** status record, it also identifies the primary key. The verifier accepts the signature only when the associated primary fingerprint equals the configured pin.

The application uses an isolated GnuPG home and checks the imported key's primary fingerprint. The public-key retrieval URL is a transport endpoint, not the trust anchor.

Do not replace the pin with a fingerprint copied from an error message. Independently verify any proposed change against F-Droid's official signing-key documentation.

## 03 · Retrieval and verification sequence

The repository client:

1. Requires HTTPS URLs and rejects redirects.
2. Applies explicit request timeouts and response-size limits.
3. Retrieves the published public-key material.
4. Imports the key into the isolated GnuPG home.
5. Confirms the expected primary fingerprint is present.
6. Retrieves index-v2.json and its detached .asc signature.
7. Verifies the detached signature against the pinned primary identity.
8. Returns index bytes only after successful verification.
9. Parses package/version records only after authentication.

The CLI reports the active retrieval phase and transfer byte counts while the index is streaming. A retrieval or signature error is fatal; unverified index bytes are never used for acquisition.

Relevant configured defaults:

| Setting | Default |
|---|---:|
| Index maximum | 128 MiB |
| Signature maximum | 1 MiB |
| Public-key maximum | 2 MiB |
| HTTP timeout | 30 seconds |

## 04 · Index data model

The root JSON object contains a **packages** mapping keyed by Android package ID. A package record contains metadata and a **versions** mapping.

Relevant version fields:

| JSON path | Meaning |
|---|---|
| **file.name** | Repository-relative APK path |
| **file.sha256** | Expected APK SHA-256 |
| **file.size** | Expected APK byte count |
| **manifest.versionName** | Human-readable version |
| **manifest.versionCode** | Numeric Android version code |
| **manifest.signer.sha256** | APK signing-certificate fingerprint(s), when present |

Version mapping keys are not assumed to be version codes. The parser operates on version records and reads **manifest.versionCode** separately.

The APK signing certificate and repository-index OpenPGP key are different identities. The former is package-signing metadata; the latter authenticates the repository index.

## 05 · Artifact verification

The index's expected SHA-256 and file size are carried into the frozen run manifest. The downloader:

- Streams one APK at a time into a temporary .part file.
- Enforces the expected byte count.
- Computes SHA-256 over downloaded bytes.
- Rejects mismatches.
- Atomically publishes the completed file only after validation.
- Appends successful acquisition to the immutable download history.

Every artifact is re-hashed before decompilation. An APK that changes after acquisition is rejected before it is passed to JADX or Apktool.

## 06 · Batch identity and processing scope

Each acquisition invocation publishes an immutable UUID run manifest before the first download. It records selected package/version identities, download URLs, expected size and SHA-256, selection order, and the digest of the authenticated index.

The **run** command passes this manifest ID to decompilation and analysis. Only artifacts that both appear in the manifest and were successfully acquired under that run ID are eligible. Failed downloads are skipped; they are not replaced by unrelated older workspace artifacts.

Standalone **decompile** and **analyze** commands without **--run-id** remain available for intentional workspace-wide processing.

## 07 · Security boundaries and limitations

- HTTPS protects transport.
- The pinned OpenPGP signature authenticates the repository index.
- SHA-256 comparison binds acquired bytes to the authenticated index entry.
- APK signer metadata is recorded as a separate identity.
- Correct provenance does not prove that an application is benign.
- Static analysis does not establish runtime behavior or exploitability.
- Scanner findings are unverified indicators because credential verification is disabled.

APK WORKBENCH does not install or execute acquired APKs. Treat APKs and all generated decompiler output as untrusted input.

## 08 · Official references

- F-Droid, All our APIs: https://f-droid.org/en/docs/All_our_APIs/
- F-Droid, Release Channels and Signing Keys: https://f-droid.org/en/docs/Release_Channels_and_Signing_Keys/
- F-Droid, Signing Process: https://f-droid.org/en/docs/Signing_Process/
- Main repository entry point: https://f-droid.org/repo/entry.json
- F-Droid server implementation: https://gitlab.com/fdroid/fdroidserver/

Additional endpoints published by F-Droid include:

~~~text
https://f-droid.org/repo/entry.json
https://f-droid.org/repo/entry.json.asc
https://f-droid.org/repo/entry.jar
https://f-droid.org/repo/signer-index.json

https://f-droid.org/archive/index-v2.json
https://f-droid.org/archive/index-v2.json.asc
~~~

Archive and incremental-index support are separate source capabilities; the current adapter uses the configured main repository's full index.
