# Project History

> **This project keeps its fingerprints.** The abandoned approaches, corrections, failed assumptions and architectural pivots are part of the engineering record. They are not cleanup targets.

APK WORKBENCH is co-developed by **dial9 + ChatGPT**. The repository is both a software project and a record of an AI-assisted engineering process: the code shows what changed; commits and pull requests show when; the decision log explains why.

## How to read this history

This is a milestone chronicle, not a claim that every conversation or local experiment is represented in Git. Commit and PR references are repository evidence. Interpretive notes explain the design evolution and should not be mistaken for a claim that a draft PR was merged or a feature was runtime-validated.

## Milestones

### 1. F-Droid: the original acquisition model

The project began as a sequential Linux-native Python workbench centered on authenticated F-Droid repository discovery, verified APK acquisition, JADX/Apktool decompilation, TruffleHog scanning and sanitized reports. Its early operating principles were deliberately conservative: one artifact at a time, one external process at a time, verify inputs, preserve records.

The initial F-Droid source-verification work established an important integrity boundary: authenticate the signed repository index before trusting its metadata, distinguish the OpenPGP index signer from Android APK signing certificates, and verify downloaded APK bytes against the index SHA-256.

**Repository evidence:** [PR #1 — Make the Python APK WORKBENCH project the default-branch deliverable](https://github.com/xdial9/apk-workbench/pull/1), merged into main by [commit 867f04e](https://github.com/xdial9/apk-workbench/commit/867f04e918197560018e38ef36d11bf67169f278) on 2026-11-07. The main-branch README and F-Droid source-verification notes document this first product shape.

### 2. Reliability becomes a first-class engineering concern

The next work concentrated on the mechanics that make a batch pipeline trustworthy: retry-safe decompilation, bounded-memory subprocess output, process-group cleanup, symlink and path defenses, retryable acquisition failures, workspace locking, immutable manifests and reconciliation after interruption.

This work is captured in [PR #2 — Integrate retry-safe and streaming decompilation](https://github.com/xdial9/apk-workbench/pull/2). Its description records 108 passing tests across Python 3.10–3.12 and Ruff success using synthetic external-tool executables. It also explicitly records the remaining boundary: real JADX/Apktool/TruffleHog binaries, a real APK corpus and sustained soak/crash-recovery validation were still required. A green synthetic integration test was not represented as production proof.

### 3. The acquisition pivot: F-Droid is no longer the only product direction

The project then explored replacing the F-Droid-only acquisition path with a Google Play Store adapter. The proposed change uses the pinned playstore-cli==0.1.1 client, discovers package IDs from Play categories/charts/searches/package lists, preserves base APKs, split APKs and OBBs, and separates the Google Play workspace from existing F-Droid data.

This is documented in [PR #3 — Google Play Store-only APK acquisition](https://github.com/xdial9/apk-workbench/pull/3). The PR description calls out that the client is an unofficial alpha and that mocked tests do not prove live account authentication or real acquisition. This PR is part of the history; it must not be described as merged into the main snapshot at commit 867f04e.

### 4. A small bug is still worth preserving

[PR #4 — Validate package IDs from discovery lists](https://github.com/xdial9/apk-workbench/pull/4) records a concrete regex over-escaping defect in discover --packages-file and the regression coverage added to correct it. This is exactly the sort of ordinary engineering mistake that belongs in the record: narrow, reproducible, fixed by a test, and useful to future maintainers.

### 5. The TruffleHog realization: a useful tool, but the wrong center of gravity

TruffleHog was initially the analysis engine because it could inspect decompiled files for credential-like material. The later architectural realization was not that TruffleHog is a bad tool. It was that **secret scanning is only one narrow category of APK analysis**. Making it the center of the product would leave the larger discovery objective unserved: manifest structure, endpoints, SDKs, cloud/vendor fingerprints, authentication/configuration indicators, WebViews, network security, crypto and dependency inventory.

The resulting decision is to retain TruffleHog as a supplementary analyzer, preserve its safe no-verification behavior and normalize its sanitized findings into a common evidence model. It is no longer the product architecture.

### 6. Airtable enters as an engineering mirror

Once the repository had enough moving parts—source files, modules, interfaces, data flow, defects, CI evidence, architecture decisions and a multi-stage roadmap—a structured coordination layer became useful. The Airtable base **APK Workbench — Engineering Map & Implementation Roadmap** was created as a shared engineering mirror for ChatGPT/Gemini collaboration and project continuity.

The initial audit pinned 47 repository files to commit 5256bd9b9ccdaa9a9834b72ea9c5802568d41088 on fix/package-file-validation. It mapped components, symbols, dependencies, data flow, tests, defects, decisions, acceptance criteria and release gates. Later, target architecture and evidence-schema specifications were added.

Airtable is not the application's runtime database. GitHub remains authoritative for code; the workbench will use local SQLite and content-addressed files for operational analysis data; Airtable remains the collaborative engineering index.

### 7. The next product: a modular Android APK workbench

The target is now broader than a TruffleHog wrapper or a single-store downloader. The workbench will preserve reliable acquisition and decompilation, then add a narrow analyzer registry, structured APK parsing, focused static extractors, isolated execution, normalized findings and precise evidence locations, explainable correlation and versioned reports.

The implementation-ready specifications are in [Target Architecture](architecture/TARGET_ARCHITECTURE.md) and [Evidence Schema](architecture/EVIDENCE_SCHEMA.md). The next work is code: SQLite models/migrations, analyzer contracts and execution orchestration. Further planning should be driven by implementation discoveries and tests, not prolonged as a separate phase.

## Repository evidence and current-state caveats

- The initial F-Droid implementation was merged to main by commit 867f04e918197560018e38ef36d11bf67169f278 on 2026-11-07. The documentation PR is based on the later main head 08f662632bd50ff3c69c9372eada3b3c320d32d4.
- The reliability, Google Play acquisition and package-list validation work is represented by PRs #2–#4 and their associated branches. Do not infer merge status from their existence; check GitHub live state before release decisions.
- The Google Play PR explicitly describes itself as a replacement for the F-Droid acquisition path. The main snapshot at the documentation PR base 08f662632bd50ff3c69c9372eada3b3c320d32d4 still documents F-Droid. The branch history is therefore essential context.
- The 108-test result cited in PR #2 used synthetic external-tool executables; it is not a real APK corpus validation.
- The laptop installation return-code-3 issue remains an operational item requiring actual laptop stderr, tool versions and command reproduction.
- MobSF and Androguard are candidates for comparative evaluation, not adopted dependencies.

## Historical preservation policy

1. Do not rewrite, squash away or delete meaningful historical commits merely to make the graph look cleaner.
2. Keep abandoned approaches and bugs visible. Correct them with later commits and tests.
3. Supersede decisions explicitly; do not erase them.
4. Keep draft PRs and branch lineage until their disposition is deliberate.
5. Distinguish implemented, tested, runtime-verified and proposed capabilities.
6. Add milestones when meaningful engineering pivots occur, with commit/PR links and the reason for the change.

**The point is not to make the project look flawless. The point is to make the work real, reproducible and understandable—including how we got things wrong and what we learned.**
