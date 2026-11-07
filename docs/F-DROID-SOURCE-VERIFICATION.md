# F-Droid Source Verification Notes

**Status:** Verified against F-Droid's official documentation and live repository entry point on 2026-11-07.
**Scope:** Initial F-Droid discovery and APK acquisition adapter.

## Decisions

1. Use the signed repository index for acquisition decisions. Do not use the per-app API v1 as the source of truth for downloads or verification; F-Droid explicitly says that API is intended for display and recommends signed index files for security-sensitive use.
2. Start with the full `index-v2.json` plus its detached `.asc` signature. Do not implement index diffs in the first adapter. Diff support can be added later as a performance optimization after full-index parsing and persistence are tested.
3. Verify the detached signature before parsing or trusting any index fields. Use an isolated GnuPG home and explicitly pin the expected primary key fingerprint. Parse GnuPG machine-readable `VALIDSIG` status; do not use `--local-user` (that selects a signing identity) and do not bypass key trust with `--trust-model always`.
4. Treat the index's APK SHA-256 as the expected artifact digest. Compute the digest after download and accept the APK only on an exact match.
5. Treat the Android APK signer certificate as a separate identity from the OpenPGP key that signs the repository index. Record signer certificate SHA-256 values from `manifest.signer.sha256` when present. A separate APK signature verification step may be implemented with Android build-tools (`apksigner`) after confirming the installed CLI interface.
6. Do not expect a base64 GPG signature embedded for each APK. The normal index data includes a file SHA-256 and APK manifest/signing-certificate metadata. F-Droid documents optional PGP package signing separately (`fdroid gpgsign`).

## Official endpoints

Main repository:

- `https://f-droid.org/repo/index-v2.json`
- `https://f-droid.org/repo/index-v2.json.asc`
- `https://f-droid.org/repo/entry.json`
- `https://f-droid.org/repo/entry.json.asc`
- `https://f-droid.org/repo/entry.jar`
- `https://f-droid.org/repo/signer-index.json`

Archive repository (separate source):

- `https://f-droid.org/archive/index-v2.json`
- `https://f-droid.org/archive/index-v2.json.asc`

The official documentation describes `entry.json` as the entry point that identifies the current full index and available diff files. It is signed by both a JAR and a GPG signature. The same documentation publishes direct GPG signatures for the index JSON files. For the first implementation, direct full-index retrieval avoids introducing diff-application logic before the basic adapter is reliable.

A live read of `https://f-droid.org/repo/entry.json` on 2026-11-07 reported:

- Entry format version: `30000`
- Full index path: `/index-v2.json`
- Full index SHA-256: `af3c06103d267a945b348cdc5668a0acab572566873ade5d1bb58c5dfa6c0eb4`
- Full index size: `72,025,232` bytes
- Package count: `4,968`
- Diff files are also advertised with timestamp, path, SHA-256, byte size, and package count.

This is useful for progress and integrity checks if the adapter later adopts `entry.json` and incremental diffs. The 72 MB full index is manageable for an initial implementation, but should be downloaded with a size limit and timeout and parsed with bounded error handling.

## Correct OpenPGP pin

F-Droid's official **Release Channels and Signing Keys** page currently documents:

- Primary OpenPGP fingerprint for `F-Droid <admin@f-droid.org>`:  
  `37D2C98789D8311948394E3E41E7044E1DBA2E89`
- Signing subkey fingerprint:  
  `802A9799016112346E1FEFF47A029E54DD5DCE7A`

The earlier project value `6BCA F632 5B11 0B08 113B 10F4 2176 52CC 92DB CD94` does **not** match the primary fingerprint or documented signing subkey above. Do not use that earlier value as the F-Droid repository-index OpenPGP pin.

When GnuPG reports a signing subkey in `[GNUPG:] VALIDSIG`, its status record also identifies the primary key fingerprint. The verifier should accept the documented signing subkey only when the associated primary fingerprint equals the configured pin. Avoid relying on human-readable `Good signature` text.

The APK signing certificate fingerprint shown for the official F-Droid client APK is yet another identity; it is not the OpenPGP index-signing fingerprint. Do not substitute one for another.

## index-v2 JSON shape

The root contains a `packages` mapping keyed by package ID. A package record contains `metadata` and a `versions` mapping. Iterate the version records using `versions.values()`; do not assume that the mapping key is the version code.

Relevant version fields include:

- `file.name`: repository-relative APK path (typically begins with `/`)
- `file.sha256`: expected APK SHA-256
- `file.size`: expected byte size
- `manifest.versionName`
- `manifest.versionCode`
- `manifest.signer.sha256`: APK signer certificate fingerprint(s), when present

The package metadata may also contain `preferredSigner`. Preserve raw signer metadata and do not assume every package has identical signer fields.

Do not hardcode a flat `packages` list or assume every version has a separate GPG signature object.

## Recommended first-pass adapter sequence

1. Download `index-v2.json` and `index-v2.json.asc` from the same configured repository origin using HTTPS, explicit timeout, bounded response size, and temporary files.
2. Verify the detached signature using the configured isolated GPG home and pinned primary fingerprint.
3. Only after successful signature verification, parse JSON and validate the root and package/version structures.
4. For each version record, normalize the repository path safely; reject absolute-path traversal, URL scheme changes, and paths escaping the repository origin.
5. Persist package ID, app name, version name/code, APK path/URL, expected SHA-256, expected size, signer certificate data, repository identity, and the raw metadata needed for audit.
6. Download selected APKs sequentially to a `.part` file. Enforce expected size, calculate SHA-256 while streaming, compare digest exactly, and only then atomically rename and append the immutable download ledger.
7. Record missing optional metadata as unknown, not as an inferred value. Fail closed on missing or malformed mandatory URL/hash fields.

## Security boundaries

- HTTPS protects transport; the pinned OpenPGP signature authenticates the index contents.
- SHA-256 comparison binds the acquired APK bytes to the authenticated index entry.
- APK signing-certificate identity is distinct from repository index signing and should be recorded/validated as a separate check.
- A matching checksum or valid signature proves integrity/provenance relative to the trusted publisher, not that an application is benign.
- F-Droid's signer index is documented as the source of truth for the SHA-256 fingerprints of signers used by `f-droid.org` to sign packages. It is signed through the entry point or direct JAR/GPG signatures; do not consume it as unauthenticated input.

## References

- F-Droid, All our APIs: https://f-droid.org/en/docs/All_our_APIs/
- F-Droid, Release Channels and Signing Keys: https://f-droid.org/en/docs/Release_Channels_and_Signing_Keys/
- F-Droid, Signing Process: https://f-droid.org/en/docs/Signing_Process/
- Live main repository entry point: https://f-droid.org/repo/entry.json
- F-Droid server implementation: https://gitlab.com/fdroid/fdroidserver/
