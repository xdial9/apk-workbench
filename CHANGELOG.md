# Changelog

## Unreleased — Google Play Store acquisition

- Make Google Play Store the sole discovery and acquisition source.
- Replace repository-index discovery with Play categories, top charts, and search.
- Capture Play delivery metadata and expected hashes before publishing each immutable run manifest.
- Preserve base APKs, split APKs, and OBB expansion files in complete per-app bundle directories.
- Independently record and process every APK component; retain and verify OBB files without passing them to APK decompilers.
- Pin the upstream alpha `playstore-cli` client and document its unofficial API, free-app limitation, and account-restriction risk.
- Remove the former repository-source adapters, configuration, tests, and documentation.
