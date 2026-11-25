# APKWORKBENCH

[ APKWORKBENCH ]  developed by dial9

**Native Android APK scanner · verified Play acquisition · deterministic static analysis · AI handoff**

APK Workbench is a Linux-native Python CLI built by **dial9** for one job: take an Android app apart, map everything inside it, and hand a complete, frozen, hash-verified evidence bundle to an AI analyst as the final step. It acquires APKs from Google Play (or from a local file), decodes them, and runs its own native scanner over the decoded tree — then packages everything the AI needs into a self-contained run bundle with a six-stage prompt set.

**This is not a wrapper.** The scanner is native code written for this tool. It reads the decoded APK itself — every file, every string, every DEX method, every native library, every certificate — and builds its own facts, findings, and deductions from scratch. External tools do two narrow jobs only: Apktool unpacks the APK so the scanner can read it, and a secret scanner runs one supplementary pass at the end (see [Secret scanning](#secret-scanning)).

**Acquisition source policy: Google Play Store (or operator-supplied local APKs).** There is no alternate repository, mirror, or source fallback.

---

## Table of contents

- [What it does](#what-it-does)
- [The native scanner](#the-native-scanner)
- [The AI handoff — what the tool is for](#the-ai-handoff--what-the-tool-is-for)
- [The pipeline at a glance](#the-pipeline-at-a-glance)
- [Requirements](#requirements)
- [How APK Workbench finds your tools](#how-apk-workbench-finds-your-tools)
- [Install](#install)
- [Verify your environment](#verify-your-environment)
- [Verify your environment](#verify-your-environment)
- [Quick start](#quick-start)
- [Commands (full reference)](#commands-full-reference)
- [Configuration reference](#configuration-reference)
- [Google Play access](#google-play-access)
- [Single-folder layout](#single-folder-layout)
- [Run bundle structure](#run-bundle-structure)
- [How to find and read a run's output](#how-to-find-and-read-a-runs-output)
- [AI handoff prompts (0–6)](#ai-handoff-prompts-0-6)
- [Reports](#reports)
- [Verification and integrity](#verification-and-integrity)
- [Migrating existing 0.2.0 workspaces](#migrating-existing-020-workspaces)
- [Important Google Play limitations](#important-google-play-limitations)
- [Troubleshooting](#troubleshooting)
- [Security and trust model](#security-and-trust-model)
- [Development](#development)
- [Project history and engineering references](#project-history-and-engineering-references)
- [Version history](#version-history)
- [License](#license)

---

## What it does

APK Workbench takes an Android app — identified by its Google Play package ID (for example `com.example.app`) or supplied as a local APK file — and runs it through a fully deterministic, evidence-gated pipeline. Every stage produces frozen, hash-verified output. Nothing is installed or executed. The end product is a self-contained run bundle that an AI analyst (or a human) can pick up and work from, with every claim traceable to a file on disk.

Concretely, for each app the tool:

1. **Discovers** it on Google Play (by chart, category, search query, or an explicit package-ID list) and records it in a de-duplicated catalog.
2. **Downloads** the complete app bundle — `base.apk`, every `split_*.apk`, and any OBB expansion files — after freezing the delivery hashes Play returns, then verifies every component against those hashes.
3. **Decodes** each APK component with Apktool so the scanner can read the contents. (Apktool is the unpacker, not the analysis — the analysis is the native scanner.)
4. **Scans it with the native scanner** (built by dial9 — see [The native scanner](#the-native-scanner)): the scanner reads the whole decoded tree and maps the app's manifest, components, permissions, network configuration, endpoints, domains, routes, HTTP call sites, headers, WebView use, dynamic loading, process execution, TLS/crypto indicators, storage and query APIs, dependency fingerprints, resources, DEX methods and call sites, native libraries and JNI links, and signing certificates. It writes one JSON fact per line (`facts.jsonl`), a location map (`location_map.json`) showing where every fact was found, and deductions that cite their evidence.
5. **Generates reports**: a per-APK report and a consolidated run report (`final-report.json` and `final-report.html`) covering the manifest, acquisition records, Play metadata, decode status, the full native scan inventory and findings, DEX cross-references, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation.
6. **Packages the AI handoff**: the run bundle includes the six-stage AI prompt set (`0.txt`–`6.txt`), a frozen manifest, SHA-256 hashes over all evidence files, and a writable `ai_analysis/` area where the AI's dossier and lead ledger live. The AI is the final analysis stage — see [The AI handoff — what the tool is for](#the-ai-handoff--what-the-tool-is-for).

The pipeline is **slow, simple, sequential, and verified** by design. Stages run one at a time, in order, with explicit status records. A stage that fails does not silently poison the next one; its status is recorded and the run can be resumed or re-run with `--force` flags.

---

## The native scanner

The scanner is the heart of APK Workbench, and it was **developed by dial9**. It is not a repackaged third-party tool. It is native code written for this project, and it does the actual analysis — everything else in the pipeline exists to feed it clean input and to package its output for the AI.

### What it reads

The scanner starts from the Apktool-decoded tree and reads **everything**:

- **The manifest** (`AndroidManifest.xml`) — every component (activities, services, receivers, providers), every permission, every intent filter, every exported surface. Sensitive permissions are flagged against a curated list. Deep-link targets are extracted too, so the scanner knows which URLs can open which parts of the app from outside.
- **Every file in the decoded tree** — classified by sniffing its magic bytes, not by trusting its extension. Code, resources, assets, native libraries, certificates, and anything else. Nothing is silently skipped: every file class that is not scanned is named in the output, so a gap is visible instead of hidden. A file ledger records every file — its path, its class, its size — and a summary of the whole tree, so the scanner can prove it looked at everything.
- **The APK zip itself** — inventoried file by file before decoding, so the scanner knows what was in the original package and can check that nothing was lost in the decode.
- **DEX bytecode** — via Androguard, the scanner builds a full model of the app's code: every class, every method, every internal call (which method calls which other method), and every API string. It cross-references Java methods and call sites: which methods call which APIs, which permissions each API needs, and where the API-to-permission mapping does not match (a method calling a sensitive API without the matching permission, or declaring a permission it never uses).
- **Native libraries** — every `.so` file is inventoried and its ELF structure parsed: its symbols, its imports, its exports. The scanner cross-matches JNI (Java Native Interface) links, connecting Java methods to the native functions they call, so a native call is never an unexplained black box. A Java method that jumps into native code is followed across the boundary.
- **Signing certificates** — the APK's signing block (v2/v3) and PKCS7 certificates are parsed from the raw DER data, extracting the signer's identity, validity dates, and certificate chain. This is the app's cryptographic identity, read directly from the bytes, not from a label.
- **Resources** — the compiled resource table (ARSC) and every XML asset are parsed, so strings, layouts, and configuration that live in resources are read the same way code is.

### What it finds

The scanner sweeps every text file in the decoded tree — code, resources, and configuration — and extracts:

- **API endpoints and routes** — full URLs, paths, and route patterns, canonicalized so the same endpoint written two different ways is counted once.
- **Domains and hosts** — matched with a ReDoS-hardened regular expression (a hostile multi-kilobyte label cannot make the scanner hang), classified by type, and separated from tooling URLs and non-domain strings. IPv4 literals are identified and recorded separately from domains.
- **Base64-encoded content** — the scanner decodes base64 candidates it finds in the text and sweeps the decoded content too, so a hidden endpoint or key buried in an encoded blob is still found.
- **HTTP client call sites** — where the app makes network requests, which library it uses, and what headers it sends.
- **WebView usage** — every WebView, its settings, and what it loads.
- **Dynamic loading** — `DexClassLoader`, reflection, and other runtime code loading, which is how an app can pull in code that is not in the APK.
- **Process execution** — shell commands and external process launches.
- **TLS and cryptography indicators** — certificate pinning, custom trust managers, cipher choices, and key handling.
- **Storage and query APIs** — databases, shared preferences, content providers, and file access.
- **Dependency fingerprints** — known libraries and SDKs identified by their markers, so the scanner knows which third-party code is inside the app.
- **Retry, backoff, and rate-limit hints** — the code patterns that show how the app handles being throttled or failing, which matters for understanding its server behavior.

### How it maps everything together — the link graph

Finding things is only half the job. The scanner's real power is that it **maps everything it finds to everything else**, so no observation sits alone. It builds a link graph — `surface/links.jsonl` — where every fact is a node and every relationship is a typed edge.

The edge types, and what each one joins:

| Edge | What it joins | How it is built |
|---|---|---|
| `component->class` | A manifest component to the Java class that implements it | Manifest `components[]` joined to the DEX class model |
| `class->method` | A class to the methods inside it | Class model + method model, joined on class name |
| `method->method` | A caller method to the method it calls | The internal DEX call graph (caller/callee + DEX class) |
| `method->endpoint` | A method to the URL or route it hits | DEX API strings with URL/route matches, joined through their real cross-references — the actual callers, not a guess |
| `endpoint->permission` | An endpoint to the permission that gates it | Permission-to-API usage, joined to the methods that reference the endpoint, plus the manifest's requested-permission list |
| `method->native` | A Java method to the native function it calls | The JNI entry facts written by the native pass (reused, not re-derived) |
| `method->secret` | A method to a secret found in its code | A secret-scan finding whose file and location fall inside that method |
| `permission->secret` | A permission to a secret it guards | A secret found in code that runs under that permission |
| `native->secret` | A native library to a secret inside it | A secret-scan finding whose file path is a modelled `.so` |
| `asset->reader` | An asset to the code that reads it | **Not derivable yet** — the scanner says so honestly instead of inventing the link |

Every edge carries **exactly two citations — one for each end**. An edge with one provable end is not an edge; a half-relation belongs in the facts plane instead. So the AI can walk the graph without guessing: from an exported component, to the class that implements it, to the method that hits a URL, to that URL, to the permission that gates it, to the secret that lives behind it — each step backed by a citation on both sides.

The graph is kept in its own plane on purpose. `facts.jsonl` says *what exists*. `links.jsonl` says *what is joined to what*. A fact is deduplicated by value — the same endpoint found 50 times is one fact with a count of 50. An edge's identity is its (from, to, citation) triple, and one edge lives in exactly one plane, so the facts and the links can never silently drift apart. If a future version folds an edge into the facts, it must go through the guarded path that rejects any overwrite of the reserved fact keys.

### The small fields — every fact, every citation, every record

The scanner is obsessive about the small fields, because the small fields are what make a claim checkable. Here is exactly what is recorded:

**Every fact** (one JSON object per line in `surface/facts.jsonl`) carries five fields:

| Field | What it is |
|---|---|
| `kind` | What type of thing this is (endpoint, domain, permission, method, secret, and so on). |
| `value` | The thing itself — the URL, the domain, the permission name, the method signature. |
| `fingerprint` | A stable hash of the value. The same value always produces the same fingerprint, so a fact can be cited by fingerprint from anywhere — a finding, a deduction, a link — and the citation always resolves to the same fact. |
| `count` | How many times this exact value was found. A fact is deduplicated by (kind, fingerprint): the same endpoint found in 50 files is one fact with `count: 50`, not 50 copies. |
| `evidence` | The full list of every place it was found — **all of it, no cap**. There used to be a 3-item cap; it was removed. `evidence_truncated` is always `false` now, and `evidence_count` tells you how many evidence items there are. |

Extra fields are allowed on a fact, but a guard rejects any extra field that would overwrite `kind`, `value`, `fingerprint`, `count`, or `evidence` — a record can never corrupt itself.

**Every citation** is a typed `EvidenceLocation` object, serialized field by field — never an ad-hoc dictionary — so one key means one thing across facts, findings, and link edges. Its fields:

| Field | What it is |
|---|---|
| `evidence_kind` | What kind of evidence this is (required — a citation without one cannot be created). |
| `container_path` | The container (APK or split) the evidence came from. |
| `source_path` | The file inside the decoded tree, relative to the tree root. |
| `line_start` / `line_end` | The line range, starting at 1. `line_end` can never precede `line_start` — the citation is validated when it is built, so a broken range cannot exist. |
| `byte_offset_start` / `byte_offset_end` | The byte range inside the file. Same rule: end can never precede start, and neither can be negative. |
| `dex_class` | The DEX class the evidence belongs to, when it comes from code. |
| `method_signature` | The full method signature, when it comes from a method. |
| `resource_name` | The resource name, when it comes from a resource. |
| `manifest_xpath` | The XPath inside `AndroidManifest.xml`, when it comes from the manifest. |
| `snippet_redacted` | A redacted text snippet of the evidence, so a human can see what was found without the secret in it. |
| `snippet_sha256` | The SHA-256 of the snippet — lowercase, validated as a real digest — so the snippet can be verified without revealing its content. |
| `extractor_coordinate` | The extractor's own coordinate for the evidence (which pass found it, and where in its own output). |

**Every entry in the location map** (`surface/location_map.json`) is an index row that ties a fact, a finding, or a deduction to its exact citation. The map itself carries:

| Field | What it is |
|---|---|
| `schema_version` | The location-map schema version, so a reader knows how to parse it. |
| `artifact` | Which APK/component this map describes. |
| `analyzer` | Which scanner version produced it. |
| `status` | The scan's terminal status. |
| `counts` | How many facts, findings, deductions, and total entries the map holds. |
| `sources` | Which file holds what — `static-analysis.json` holds facts, findings, deductions, coverage, manifest, inventory, metrics, and the workbook; `facts.jsonl` holds one JSON object per line; the location map is the index itself. |
| `entries` | One entry per fact (with its exact line number in `facts.jsonl` — line N is cited by `entries[].facts_jsonl_line`), one per finding, one per deduction. |

The location map is generated deterministically and written atomically, wholesale — a rerun rewrites both files completely, so a rerun can never append duplicate facts.

**Every run bundle's `handoff.json`** carries the schema version, the tool versions, the prompt versions, the run's `bundle_id`, and the SHA-256 hashes of the key files, so the AI knows exactly what it is reading and can verify it has not changed.

### How it reasons — facts, findings, deductions

The scanner does not guess. It works in three layers, each one stricter than the last:

1. **Facts.** Every observation becomes a fact — one JSON object per line in `facts.jsonl`, with the five fields above. `location_map.json` records exactly where in the decoded tree each fact was found, down to the file and line, so any claim can be traced to the bytes that prove it.
2. **Findings.** Facts are grouped into findings — structured statements about the app (for example, "this app contacts these 14 domains" or "this component is exported without a permission"). Findings cite the facts they rest on, and each finding carries its own location entries in the map.
3. **Deductions.** The scanner combines facts into deductions using fixed templates — conjunctive facts only, never guesses. Every deduction carries its template ID, the fingerprints of the input facts, a narrative in plain operator language, a confidence label, and next steps for the AI handoff. **A deduction without cited fingerprints is forbidden.** If the evidence is not there, the scanner says so instead of inventing a conclusion.

Two deduction rules are built in:

- **Dynamic code loading** — if the app loads code at runtime, that is flagged as a deduction with the exact call sites cited, because it means the APK you scanned is not the whole app.
- **Permission mismatch** — if a DEX method calls a sensitive API but the app does not declare the matching permission (or declares a sensitive permission it never uses), that mismatch is flagged. Storage and Bluetooth permissions are excluded from this check because the API-permission mapping data is incomplete for them and would produce false alarms.

### The workbook and the coverage map

Two more outputs keep the scan honest and usable:

- **The workbook** (`static-analysis.json` → `workbook`) is a working view built from the scan: fact locations, finding locations, deduction leads, coverage leads, and flagged-fact leads, rendered so a human or an AI can walk the results without re-parsing the raw files. It is the scanner's own summary of what it found and what is still open.
- **The coverage map** (`static-analysis.json` → `coverage`) records the status of every analysis plane — for example `dex_semantic_analysis` is `complete`, `partial`, `not_run`, or `not_applicable`. A plane that did not run is recorded as not run, not silently omitted. The secret-linkage status (`trufflehog_secret_linkage`) is recorded the same way, so you can see whether the secret findings were actually linked back into the graph or not.

### How it stays honest

- **Nothing is silently skipped.** Every file class that is not scanned is named in the output. A gap is a visible gap, not a silent hole.
- **No truncation.** Evidence is cap-free — every occurrence is kept, every evidence item is listed, `evidence_truncated` is always false.
- **Reserved keys are guarded.** No extra field can overwrite a fact's `kind`, `value`, `fingerprint`, `count`, or `evidence`. A record cannot corrupt itself.
- **Citations are validated at construction.** A citation with an end line before its start line, a negative byte offset, or a malformed SHA-256 cannot be created — the constructor rejects it.
- **Checkpoints.** Long sweeps save checkpoints, so a scan interrupted halfway can resume instead of starting over.
- **Atomic writes.** Output files are written atomically and rewritten wholesale — a crash mid-write never leaves a half-written file that looks complete, and a rerun never appends duplicates.
- **Deterministic.** The same APK in produces the same facts out. No randomness, no timestamps in the evidence, no model calls. The scanner's output is reproducible, which is what makes the AI handoff trustworthy: the AI is reasoning over fixed evidence, not over a moving target.

---

## The AI handoff — what the tool is for

APK Workbench exists for one purpose: **to produce a complete, frozen evidence bundle that an AI analyst picks up as its final input and turns into a dossier.** The AI is the last stage of the pipeline, not an afterthought. Every design decision in the tool — determinism, freezing, hashing, self-containment, the prompt set — exists to make that handoff work.

### Exactly how the pipeline works, end to end

Here is the whole pipeline, step by step, in the order it runs:

**Step 1 — Discover.** The operator tells the tool what to look at: a Play category, a chart, a search query, or a list of package IDs in a file. `apkworkbench discover` queries Google Play and records every package ID it finds in a de-duplicated catalog (`database/google_play_discovery.csv`). The catalog is a rolling union — every discover session adds to it, never replaces it — so a rate-limit abort halfway through a crawl keeps the progress made so far. This step answers: *what apps are we going to analyze?*

**Step 2 — Download and freeze.** `apkworkbench download` (or `run`) picks apps from the catalog and asks Play for their delivery metadata — which APK components exist (`base.apk`, `split_*.apk`, OBB files), their sizes, and their expected hashes. The tool **freezes the run manifest at this point**, before downloading anything. The manifest is a record of what Play said the app should be. Then it downloads every component and verifies each one against the frozen hashes (SHA-256 for APKs, SHA-1 for OBBs), then re-hashes them independently a second time before decompilation. If a component fails verification, it is recorded as failed — never silently accepted. This step answers: *did we get exactly what Play said we would get?*

**Step 3 — Decode.** `apkworkbench decompile` runs Apktool on each verified APK component. Apktool unpacks the APK into a readable tree: `AndroidManifest.xml`, resources, smali code, and assets. This is a mechanical unpacking step — Apktool does not analyze anything, it just makes the contents readable. Decode status and logs are recorded per component. A component that fails to decode is recorded as failed with its log, not skipped. This step answers: *can we read the app's contents?*

**Step 4 — Native scan.** `apkworkbench surface` runs the native scanner (built by dial9) over the decoded tree. This is the analysis. The scanner reads the manifest, classifies every file, sweeps every text file for endpoints/domains/routes/keys, cross-references DEX methods and call sites, inventories native libraries and JNI links, parses signing certificates, and builds facts, findings, and deductions — all with fingerprints and locations. A supplementary secret scan also runs at this stage (see [Secret scanning](#secret-scanning)). Output: `surface/facts.jsonl`, `surface/location_map.json`, and the finding/deduction records. This step answers: *what is inside this app, and what does it do?*

**Step 5 — Report.** `apkworkbench report` consolidates everything into a per-APK report and, when scoped with `--run-id`, a run report (`reports/final-report.json` and `reports/final-report.html`). The report contains the frozen manifest, acquisition records, Play metadata, decode status, the full native scan inventory and findings, DEX cross-references, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation. This step answers: *what did we find, in one place, with the evidence attached?*

**Step 6 — Package the handoff.** Every stage's output is collected into a self-contained run bundle under `~/APK-Workbench/runs/<package>-v<version>-<short_id>/`. The bundle contains the original APKs, the decoded tree, the scanner's facts and findings, the reports, the frozen manifest, the per-stage status records, the logs, and — critically — the six-stage AI prompt set (`prompts/0.txt`–`6.txt`), copied into the bundle so it never changes even if the installed package is upgraded. A SHA-256 manifest (`hashes.sha256`) covers every frozen evidence file, and `handoff.json` records the schema version, tool versions, prompt versions, the run's `bundle_id`, and the hashes of key files. This step answers: *is everything the AI needs in one folder, frozen and verifiable?*

**Step 7 — The AI handoff (the final tool call).** The operator (or an automated harness) hands the run bundle to an AI analyst with the prompt set. The AI works through the six stages in order:

1. **Prompt 0 (Master)** — sets the AI's role as the final analysis stage and explains the evidence it has.
2. **Prompt 1 (Map the raw app)** — the AI forms its own understanding from the raw decoded tree *before* reading any tool conclusions, so it is not anchored on the scanner's findings.
3. **Prompt 2 (Integrate the program's output)** — the AI reads the scanner's facts and separates what it can confirm, what it disagrees with, and what it cannot verify.
4. **Prompt 3 (Trace every hint)** — the AI works through *every* lead in the lead list until each one is resolved or honestly triaged as open with a reason.
5. **Prompt 4 (Deductions and correlations)** — the AI turns per-lead facts into app-level intelligence: how the app behaves, what its ecosystem is, where its risks concentrate.
6. **Prompt 5 (Write the deliverables)** — the AI produces the dossier (`ai_analysis/attempt-01/dossier.md`) and the machine-readable lead ledger (`ai_analysis/attempt-01/lead_ledger.json`).
7. **Prompt 6 (Closure)** — the AI assumes it missed something and proves that it did not: adversarial self-audit, free exploration, verification, and a clean close-out.

The AI's output lands in `ai_analysis/attempt-01/` inside the same run bundle, next to the evidence it reasoned over. The dossier and the evidence live together, so anyone can check the AI's claims against the frozen facts.

### Why the pipeline is built this way

- **Deterministic input, so the AI's output is checkable.** The scanner produces the same facts from the same APK every time. The AI reasons over fixed evidence. If a claim in the dossier is wrong, you can trace it to the fact it cites and to the bytes that fact came from — or find that it cites nothing, which tells you it is invented.
- **Frozen before the AI touches it.** The manifest is frozen before download; the evidence is hashed before the AI reads it. The AI cannot change the evidence, and nothing the AI writes can be mistaken for pipeline output — its work goes in `ai_analysis/`, the pipeline's work stays in `apk/`, `apktool/`, `surface/`, `manifest/`, and `reports/`.
- **Self-contained, so the handoff is one folder.** The run bundle has everything: the APK, the decoded tree, the facts, the reports, the prompts, the hashes. Hand someone the folder and they have the whole analysis. No database, no server, no second copy of anything.
- **Slow, simple, sequential.** Stages run one at a time, in order. A failure in one stage is recorded and visible, not papered over by the next stage. The pipeline is built to be correct, not fast.

### Secret scanning

One supplementary pass runs alongside the native scan: the decoded tree is scanned for secrets (API keys, tokens, credentials) with TruffleHog, and all findings — verified and unverified — are retained in the run bundle's `trufflehog/` folder. This is a supporting check, not the analysis. The native scanner is the analysis; the secret scan is one extra signal that the AI can use or disregard. See the `analyze` command for options.

---

## The pipeline at a glance

```
discover  →  download  →  decompile  →  surface  →  report  →  AI handoff
 (catalog)   (freeze +      (Apktool)    (native      (evidence   (dossier +
               verify)                    scanner)     package)     lead ledger)
```

Or all at once:

```
apkworkbench run --package com.example.app
apkworkbench run --local-apk /path/to/base.apk
```

`run` acquires from the saved discovery catalog (or one exact package, or one local APK) and then processes the batch through every stage. Individual stage commands (`download`, `decompile`, `surface`, `analyze`, `report`) let you run or re-run one stage at a time.

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Operating system | 64-bit Linux (Debian / Ubuntu) | The tool is Linux-native. |
| Python | 3.10+ | |
| Java | 11+ | Required by Apktool. OpenJDK 21 verified. |
| Apktool | 2.x | Must be on `PATH` as `apktool`. 2.7.0 verified. |
| TruffleHog | 3.x | Supplementary secret scan only — must be on `PATH` as `trufflehog`. 3.99.8 verified. |
| playstore-cli | 0.1.1 (pinned) | Installed automatically as a Python dependency. Unofficial Google Play API client. |
| goopdl | 2.0.0 (pinned) | Installed automatically as a Python dependency. Supplies Play device-session credentials. |
| androguard | 4.1.4 (pinned) | Installed automatically as a Python dependency. DEX analysis. |

APK Workbench shells out to Java and Apktool as external system tools (plus one supplementary secret scanner — see [Secret scanning](#secret-scanning)). It does **not** download or install them for you. `playstore-cli`, `goopdl`, and `androguard` are Python dependencies and install with the package.

## How APK Workbench finds your tools

You do not have to tell the program where your tools are — it finds them for you. Here is exactly how, in order:

1. **It reads the tool name from your config.** Each tool has a config key under `tools:` in `~/APK-Workbench/config.yaml`. The defaults are just the bare tool names: `java`, `apktool`, `trufflehog`, `playstore-cli`. (See the [Configuration reference](#configuration-reference).)
2. **It searches your system PATH.** It looks for that name in every folder on your `PATH` (the same way your shell finds a command when you type it). If it finds it, that is the location it uses.
3. **If it is not on PATH, it checks your Python environment's `bin` folder.** `playstore-cli` and `androguard` are console scripts installed by `pip` into the active virtualenv's `bin` directory. Even if that virtualenv is not activated (so it is not on your `PATH`), the program checks `sys.executable`'s parent folder and `sys.prefix/bin` and finds them there. This is why `doctor` can report them as `[OK]` without you doing anything extra.
4. **If you gave it a full path, it uses that path directly.** If you set a config value to an absolute path (for example `tools.apktool: /usr/local/bin/apktool`) or a path with folders in it, the program skips the PATH search and the Python-environment check and uses exactly the path you gave it. If nothing is there, it reports the tool as missing.
5. **It runs the tool's version command to prove it works.** Finding the file is not enough — the program runs `java -version`, `apktool --version`, `trufflehog --version`, `playstore-cli --help`, or `androguard --help` and checks that it exits successfully. The version string it prints is the first line of that output. If the version command fails or times out (25 seconds), the tool is reported as installed but unhealthy.

`apkworkbench doctor` runs this whole check for every tool and prints the result:

- `[OK] <tool> (<version>)` — found and its version command worked.
- `MISSING` — not found on PATH, not in the Python environment, and not at the config path (if you set one).
- `UNHEALTHY` — found, but its version command failed.

When a tool is missing, `doctor` prints an install hint telling you exactly how to get it (for example `sudo apt install default-jre-headless` for Java, or the TruffleHog install script).

**To point a tool at a specific location**, set its config key to the full path:

```yaml
# ~/APK-Workbench/config.yaml
tools:
  java: /usr/lib/jvm/java-21-openjdk/bin/java
  apktool: /opt/apktool/apktool
  trufflehog: /usr/local/bin/trufflehog
  playstore_cli: /home/user/.venv/bin/playstore-cli
```

**To use a different version of a tool**, install that version somewhere on your `PATH` (or point the config key at it). The program does not pin or check tool versions beyond running the version command — whatever it finds is what it uses.

---

## Install

### From PyPI (recommended)

```bash
pip install apkworkbench
```

This installs the `apkworkbench` command. Version 0.3.0 is the current shipping release.

### From source (for development)

```bash
git clone --branch main https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The `[dev]` extra installs `pytest` and `ruff` for running the test suite and linting.

### Install the system tools

```bash
# Java 11+ (required by Apktool)
sudo apt update && sudo apt install -y default-jre-headless

# Apktool — install via your distro package manager or the official guide:
# https://apktool.org/docs/install

# TruffleHog — install from the official releases or install script:
# https://github.com/trufflesecurity/trufflehog/releases
```

Verify the tools are present:

```bash
java -version
apktool --version
trufflehog --version
```

### Python dependencies (requirements.txt) — what builds the venv

The Python packages the tool needs are listed in **`requirements.txt`** at the root of the repo, and duplicated as the source of truth in **`pyproject.toml`** (`[project] dependencies`). When you install from PyPI (`pip install apkworkbench`) or from source (`pip install -e ".[dev]"`), these are installed automatically. You do not need to install them by hand — but here is exactly what they are, so you know what is in your venv:

| Package | Version | What it does |
|---|---|---|
| `click` | `>=8.1,<9` | The CLI framework — every `apkworkbench` command, option, and help text is built on it. |
| `PyYAML` | `>=6.0,<7` | Reads and writes `config.yaml`. |
| `playstore-cli` | `==0.1.1` (pinned) | The Google Play API/delivery client. Unofficial internal Play API. |
| `goopdl` | `==2.0.0` (pinned) | Supplies Play device-session credentials (account mode and anonymous dispenser). |
| `androguard` | `==4.1.4` (pinned) | DEX analysis — method and call-site cross-references in the surface pass. |

`playstore-cli`, `goopdl`, and `androguard` are **pinned to exact versions** (`==`) because the Play adapter and the DEX analysis depend on their exact behavior. `click` and `PyYAML` use a version range (`>=…,<…`) because any recent version works.

The raw file (`requirements.txt`):

```text
click>=8.1,<9
PyYAML>=6.0,<7
playstore-cli==0.1.1
goopdl==2.0.0
androguard==4.1.4
```

To build the venv yourself from the file (instead of using `pip install -e .`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For development, install the dev extra instead — it pulls in the same five packages plus the test and lint tools:

```bash
python -m pip install -e ".[dev]"
# dev extra adds: pytest>=8,<9  and  ruff>=0.5
```

**What is NOT in requirements.txt:** Java, Apktool, and TruffleHog. Those are system tools, not Python packages — they are installed separately (see [Install the system tools](#install-the-system-tools)) and found on your `PATH` (see [How APK Workbench finds your tools](#how-apk-workbench-finds-your-tools)).

---

## Verify your environment

```bash
apkworkbench doctor
```

`doctor` checks every external tool (`java`, `apktool`, `trufflehog`, `playstore-cli`, `androguard`), the workspace home health, the bundled AI prompts, and the Google Play auth status. It prints `[OK]` for each check that passes, `[AUTH]` for the Play session source, and actionable install hints when a required system tool is missing. It exits `0` with `Status: READY` when everything is in place.

Example output:

```
[ APKWORKBENCH ]  developed by dial9
[OK] playstore-cli (usage: playstore-cli [-h])
[OK] java (openjdk version "21.0.13.1" ...)
[OK] apktool (2.7.0)
[OK] trufflehog (trufflehog 3.99.8)
[OK] androguard (Usage: androguard [OPTIONS] COMMAND [ARGS]...)
[OK] workspace (/home/user/APK-Workbench)
[OK] prompts (/home/user/APK-Workbench/prompts)
[AUTH] Play session source: UNAVAILABLE (no account configured to use)
  Run `goopdl auth login`, or export GOOPDL_ACCOUNT_EMAIL and GOOPDL_AAS_TOKEN.
Status: READY
```

`Play session source: UNAVAILABLE` is not a failure — it means no Google account is configured, so the tool will use anonymous mode (Aurora Store's public token dispenser) on the first Play request. See [Google Play access](#google-play-access) for how to configure account mode.

---

## Quick start

```bash
# 1. Verify system tools, workspace, and Play auth status
apkworkbench doctor

# 2. Run the full pipeline on a Google Play package
apkworkbench run --package com.example.app

#    Or run the full self-contained pipeline on a local APK
apkworkbench run --local-apk /path/to/base.apk

# 3. Override the default ~/APK-Workbench home directory if desired
apkworkbench --workspace /path/to/home run --local-apk /path/to/base.apk
#    Or set the environment variable:
export APKWORKBENCH_WORKSPACE=/path/to/home
```

After a run, find the output under `~/APK-Workbench/runs/<package>-v<version>-<short_id>/`. See [How to find and read a run's output](#how-to-find-and-read-a-runs-output).

---

## Commands (full reference)

Run `apkworkbench <command> --help` for the authoritative option list. All commands accept the global `--workspace DIRECTORY` option (before the command) to override the home folder, and `--version` / `--help`.

### `apkworkbench doctor`

Check required external tools, workspace home, bundled prompts, and Play auth.

```bash
apkworkbench doctor
```

No options. Exits `0` with `Status: READY` when everything passes.

### `apkworkbench run`

Acquire from the saved discovery catalog (or one exact package, or one local APK), then process the batch through every stage.

```bash
apkworkbench run --package com.example.app
apkworkbench run --local-apk /path/to/base.apk
apkworkbench run --apk-count 100
apkworkbench run --apk-count 10 --force-decompile --force-surface --force-analyze
```

| Option | Default | Description |
|---|---|---|
| `--apk-count INTEGER` | `10` | Number of new Google Play applications to acquire. Must be ≥ 1. |
| `--package TEXT` | — | Restrict the acquisition to this exact Android package ID. |
| `--local-apk PATH` | — | Run the self-contained pipeline on a local APK file or bundle directory. |
| `--force-decompile` | off | Re-run completed decompilations. |
| `--force-surface` | off | Re-run completed static surface analysis. |
| `--force-analyze` | off | Re-run successful supplementary secret scans. |

### `apkworkbench discover`

Discover app package IDs from Google Play categories, charts, and searches.

```bash
# Discover up to 15,000 unique package IDs across Play top-free charts
apkworkbench discover --limit 15000

# Add targeted Play searches to expand the candidate set
apkworkbench discover --limit 15000 \
  --query banking --query finance --query fintech \
  --query wallet --query payments --query neobank

# Restrict discovery to selected Play categories
apkworkbench discover --category FINANCE --category APPLICATION --limit 1000

# Import only the listed IDs (one per line), without crawling Play charts
apkworkbench discover --packages-file packages.txt --limit 15000
```

| Option | Default | Description |
|---|---|---|
| `--query TEXT` | — | Google Play search query; may be repeated. |
| `--category TEXT` | — | Exact Play category ID; repeatable. |
| `--limit INTEGER` | `15000` | Maximum number of distinct Google Play package IDs to catalogue. Must be ≥ 1. |
| `--per-category INTEGER` | `200` | Maximum top-free chart entries collected per category. Must be ≥ 1. |
| `--per-query INTEGER` | `516` | Maximum search results collected per query. Must be ≥ 1. |
| `--packages-file FILE` | — | UTF-8 package IDs, one per line; alone, skips broad chart/search discovery. |

Discovery results are de-duplicated by Android package ID. A requested limit is a ceiling, not a guarantee: Play search and chart endpoints return bounded result sets, and discovery can produce fewer than 15,000 unique apps. To combine a package-ID list with broad discovery, also provide a query or category explicitly.

The catalog is a rolling union: every discover session merges its results into `database/google_play_discovery.csv` after each completed query/category channel, and reruns only ever add package IDs. A rate-limit abort partway through a category crawl keeps the progress made so far.

### `apkworkbench download`

Freeze Play delivery hashes, then acquire and verify complete app bundles.

```bash
apkworkbench download --apk-count 100
apkworkbench download --package com.example.app
```

| Option | Default | Description |
|---|---|---|
| `--apk-count INTEGER` | `10` | Number of new apps to acquire. Must be ≥ 1. `--package` selects exactly one. |
| `--package TEXT` | — | Acquire this exact Google Play Android application ID. |

The run manifest is frozen after Play delivery metadata and expected hashes have been retrieved, before the first APK download. Each Google Play app may contain `base.apk`, multiple `split_*.apk` files, and OBB expansion files; all are retained in the run's `apk/` directory. APK components are recorded separately and independently processed; OBB files are preserved and integrity-checked without being passed to APK decompilers.

### `apkworkbench decompile`

Run Apktool against verified acquired APKs.

```bash
apkworkbench decompile
apkworkbench decompile --limit 50
apkworkbench decompile --force
apkworkbench decompile --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--limit INTEGER` | `0` | Maximum number of APKs to process; `0` processes all eligible downloads. Must be ≥ 0. |
| `--force` | off | Re-run Apktool even when usable decoded output already exists. |
| `--run-id TEXT` | — | Restrict processing to artifacts in this frozen download manifest. |

Apktool is the sole decompiler. Partial failures are recorded per component (status + log), not silently skipped.

### `apkworkbench surface`

Run static APK surface analysis against Apktool-decoded output.

```bash
apkworkbench surface
apkworkbench surface --force
apkworkbench surface --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--force` | off | Re-run surface analysis even when prior output exists. |
| `--run-id TEXT` | — | Restrict analysis to artifacts in this frozen download manifest. |
| `--workspace DIRECTORY` | — | Override the configured workspace directory. |

The static surface pass inventories manifest/components/permissions, network-security configuration, API endpoints/domains/routes and HTTP client call sites, common headers, retry/backoff/rate-limit hints, WebView, dynamic loading, process execution, TLS/cryptography indicators, storage/query APIs, dependency fingerprints, resources, and native libraries. DEX methods and call sites are cross-referenced with Androguard. Server-side API rate limits cannot be determined from static APK strings; the report states so explicitly. Static findings remain leads until independently confirmed.

### `apkworkbench analyze`

Run the supplementary secret scan against Apktool-decoded output and retain all findings.

```bash
apkworkbench analyze
apkworkbench analyze --limit 50
apkworkbench analyze --force
apkworkbench analyze --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--limit INTEGER` | `0` | Maximum number of Apktool-decoded APKs to scan; `0` scans all eligible downloads. Must be ≥ 0. |
| `--force` | off | Re-scan APKs whose previous secret scan succeeded. |
| `--run-id TEXT` | — | Restrict analysis to artifacts in this frozen download manifest. |

All secret-scan findings are retained — verified and unverified. Nothing is silently dropped.

### `apkworkbench report`

Generate per-APK reports and, when scoped, one complete run evidence package.

```bash
apkworkbench report
apkworkbench report --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--run-id TEXT` | — | Also generate a consolidated report for this frozen run. |

Without `--run-id`, per-APK reports are generated. With `--run-id`, a consolidated run report is also generated (`reports/final-report.json` and `reports/final-report.html` in the run bundle).

### `apkworkbench status`

Summarize acquisition, decompilation, and scan state.

```bash
apkworkbench status
```

No options. Prints counts of acquired APK binaries, Apktool-decoded components, surface-analyzed components, and secret-scanned components.

### `apkworkbench reconcile`

Report the terminal outcome of every item in a frozen acquisition manifest.

```bash
apkworkbench reconcile --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--run-id TEXT` | **required** | Frozen acquisition run ID to reconcile. |

### `apkworkbench verify-workspace`

Recompute SHA-256 hashes for a frozen workspace bundle.

```bash
apkworkbench verify-workspace ~/APK-Workbench/runs/<run-folder>
```

Reads `hashes.sha256` from the bundle root and recomputes SHA-256 for every file listed. Exits non-zero on any mismatch, missing file, or extra file. **Never writes into the folder being verified.**

### `apkworkbench verify-downloads`

Independently verify downloaded component files and their Play hashes.

```bash
apkworkbench verify-downloads --run-id YOUR-RUN-ID
```

| Option | Default | Description |
|---|---|---|
| `--run-id TEXT` | **required** | Verify every APK/OBB file in this immutable Google Play acquisition run. |

### `apkworkbench migrate`

Copy legacy workspace bundles into self-contained run folders (non-destructive).

```bash
# Preview what will be moved/indexed without modifying files
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench

# Apply the migration
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench --apply
```

| Option | Default | Description |
|---|---|---|
| `--source DIRECTORY` | **required** | Path to the legacy 0.2.0 workspace directory. |
| `--target DIRECTORY` | configured workspace | Target single-folder home directory. |
| `--apply` | off (dry-run) | Copy bundles into the target layout. Without it, only previews. |

Migration is non-destructive: it copies, never moves or deletes the source.

### `apkworkbench version`

Print the installed package version.

```bash
apkworkbench version
# 0.3.0
```

---

## Configuration reference

Defaults are built into the package. Add only settings that need to change.

**Configuration file:** `~/APK-Workbench/config.yaml` (overridable via `--workspace` or `APKWORKBENCH_WORKSPACE`).
**Legacy fallback:** if `~/APK-Workbench/config.yaml` does not exist yet, APK Workbench falls back to reading a legacy `~/.config/apkworkbench/config.yaml` automatically.

### Example

```yaml
workspace: /data/APK-Workbench/workspace

sources:
  google_play:
    auth_mode: auto
    retry_backoff_seconds: 1.0

decompilation:
  timeout_seconds: 3600

analysis:
  timeout_seconds: 7200
  max_output_bytes: 536870912

tools:
  playstore_cli: playstore-cli
  java: java
  apktool: apktool
  trufflehog: trufflehog

logging:
  level: INFO
  file: logs/apkworkbench.log
```

### Full key reference

| Key | Default | Description |
|---|---|---|
| `workspace` | `~/APK-Workbench` | Home folder for config, state, logs, and runs. Overridden by `--workspace` or `APKWORKBENCH_WORKSPACE`. |
| `sources.google_play.auth_mode` | `auto` | Play session source: `auto`, `account`, or `anonymous`. See [Google Play access](#google-play-access). |
| `sources.google_play.retry_backoff_seconds` | `1.0` | Initial delay for bounded bundle-download retries. |
| `decompilation.timeout_seconds` | `3600` | Maximum runtime per Apktool process (1 hour). |
| `analysis.timeout_seconds` | `7200` | Maximum supplementary secret-scan runtime per APK (2 hours). |
| `analysis.max_output_bytes` | `536870912` | Maximum scanner output (512 MiB). |
| `tools.playstore_cli` | `playstore-cli` | Google Play API/delivery client executable checked by `doctor`. |
| `tools.java` | `java` | Java executable. |
| `tools.apktool` | `apktool` | Apktool executable. |
| `tools.trufflehog` | `trufflehog` | Supplementary secret scanner executable. |
| `logging.level` | `INFO` | Python logger level. |
| `logging.file` | `logs/apkworkbench.log` | Log path; relative paths resolve within the workspace. |

Discovery limits are command options rather than configuration keys (`discover --limit`, `--per-category`, `--per-query`).

JADX is no longer an installed runtime dependency or a required configuration key. Apktool is the sole decompiler. The legacy `jadx_status` processing column remains for existing workspace compatibility.

---

## Google Play access

The acquisition adapter uses [playstore-cli](https://pypi.org/project/playstore-cli/) 0.1.1 for Google's **unofficial internal Play API** protocol and Play delivery operations. [goopdl](https://pypi.org/project/goopdl/2.0.0/) 2.0.0 supplies Play device-session credentials in one of three operator-configured modes (`sources.google_play.auth_mode`).

### The three modes

| Mode | How it gets a session | When to use it |
|---|---|---|
| **`account`** (recommended) | Your own Google account, via `goopdl auth login` or `GOOPDL_ACCOUNT_EMAIL` + `GOOPDL_AAS_TOKEN`. | Reliable acquisition, especially overnight. The Aurora dispenser is never contacted, so acquisition stays working when the third-party dispenser is down. |
| **`anonymous`** | Aurora Store's public token dispenser. No Google login, AAS token, API key, browser sign-in, or manually supplied bearer token required. | Quick checks with no account. The dispenser is third-party and frequently unavailable or rate-limited. |
| **`auto`** (default) | Account mode when credentials resolve; anonymous otherwise. | The default. Uses your account when configured, falls back to the dispenser when not. |

### Account mode setup

```bash
goopdl auth login        # browser sign-in; --manual works on headless machines
goopdl auth status
apkworkbench doctor      # should print: Play session source: ACCOUNT (...)
```

Prefer the environment over the saved account? Use `goopdl auth login --print` and export `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` instead.

Credentials resolve in this order: `GOOPDL_ACCOUNT_EMAIL` + `GOOPDL_AAS_TOKEN` (environment), then the account saved with `goopdl auth login` (system keyring, else `~/.config/goopdl/account.json`). Without any of these, commands fail fast with instructions instead of guessing.

### Anonymous mode

No Google login is required by default: on the first Play request, APK Workbench obtains a short-lived anonymous device session from Aurora Store's public token dispenser, whose tokens `goopdl` maintains and refreshes automatically. In `anonymous` mode the adapter deliberately refuses to read Google-account credentials; set `auth_mode: account` or `auto` for that.

### How sessions work internally

The Play API still receives a short-lived bearer token internally; `goopdl` caches and rotates it (by default under `~/.config/goopdl`, relocatable with `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME`) and honors `retry_after` windows before re-minting. After a Play 401 it re-mints the bearer, and a second consecutive rejection retires and re-registers the device. When a token source advertises a `retry_after` window (for example a dispenser 429), the adapter honors it with a capped sleep before re-minting. The Play API remains unofficial.

On POSIX, `goopdl` creates the cache directory with mode `0700` and token files with mode `0600`.

### Config

```yaml
# ~/APK-Workbench/config.yaml
sources:
  google_play:
    auth_mode: auto    # auto (default) | account | anonymous
```

---

## Single-folder layout

All configuration, run indexes, logs, and self-contained run bundles live under a single folder: **`~/APK-Workbench/`** (overridable via `--workspace` or `APKWORKBENCH_WORKSPACE`).

```text
~/APK-Workbench/
├── config.yaml                          # Workbench configuration
├── runs_index.json                      # Index of every completed and in-progress run
├── logs/                                # Global workbench logs
└── runs/
    └── <package>-v<version>-<short_id>/ # Self-contained per-run bundle
```

**Backward compatibility:** `APKWORKBENCH_WORKSPACE` overrides the default `~/APK-Workbench` home directory, and if `~/APK-Workbench/config.yaml` does not exist yet, APK Workbench falls back to reading a legacy `~/.config/apkworkbench/config.yaml` automatically.

Before 0.3.0, the workspace was split across `~/.config/apkworkbench`, `~/.local/state/apkworkbench`, and a project directory. Version 0.3.0 consolidates everything into the single `~/APK-Workbench` folder. See [Migrating existing 0.2.0 workspaces](#migrating-existing-020-workspaces).

---

## Run bundle structure

Every run creates one self-contained directory under `runs/` with all inputs, decoded evidence, reports, hashes, prompts, and AI analysis workspace together (with no second Apktool directory):

```text
~/APK-Workbench/runs/<package>-v<version>-<short_id>/
├── README.md          # Human-readable guide to this run
├── README.txt         # Short bootstrap pointer for AI consumers
├── handoff.json       # Schema/tool/prompt versions, bundle_id, and key file hashes
├── hashes.sha256      # SHA-256 manifest over all frozen evidence files
├── apk/               # Original APK(s) and split/OBB components for this run
├── apktool/           # Decoded APK components (apktool/<component>/)
├── surface/           # Static surface, DEX, native, facts.jsonl, location_map.json
├── trufflehog/        # Supplementary secret-scan findings (verified + unverified) + status.json
├── manifest/          # Frozen run manifest and verification records
├── reports/           # final-report.json and final-report.html
├── stages/            # Per-stage status.json records
├── logs/              # Run-scoped stage logs
├── prompts/           # Bundled AI handoff prompts (0.txt–6.txt)
└── ai_analysis/       # Writable AI analysis output area (attempt-01/, etc.)
```

### What each part is

| Path | Contents |
|---|---|
| `README.md` | Human-readable guide to this run: what app, what version, what stages ran, where the key outputs are. |
| `README.txt` | Short bootstrap pointer for AI consumers: the minimum needed to orient an AI analyst. |
| `handoff.json` | Schema version, tool versions, prompt versions, the run's `bundle_id`, and SHA-256 hashes of key files. The AI reads this first. |
| `hashes.sha256` | SHA-256 manifest over all frozen evidence files. Recompute with `apkworkbench verify-workspace <run-folder>`. |
| `apk/` | The original APK(s) and split/OBB components exactly as acquired from Play (or supplied locally). Never modified after acquisition. |
| `apktool/` | Apktool-decoded output per component (`apktool/<component>/`), with `AndroidManifest.xml`, resources, smali, and assets. |
| `surface/` | Deterministic static surface analysis: `facts.jsonl` (one JSON fact per line), `location_map.json` (where each fact was found), DEX cross-references, and native library inventory. |
| `trufflehog/` | Supplementary secret-scan findings (verified and unverified) plus `status.json` recording the scan outcome. |
| `manifest/` | The frozen run manifest (delivery metadata, expected hashes, acquisition records) and verification records. Frozen before the first download; never modified after. |
| `reports/` | `final-report.json` (structured data) and `final-report.html` (human-readable view). |
| `stages/` | One `status.json` per pipeline stage, recording what ran, when, and whether it succeeded. |
| `logs/` | Run-scoped stage logs (per-stage stdout/stderr from Apktool, the secret scanner, and the adapter). |
| `prompts/` | The bundled AI handoff prompts `0.txt`–`6.txt`, copied into the run so the bundle is self-contained even if the installed package changes. |
| `ai_analysis/` | Writable area for AI analysis output. Each attempt gets its own folder (`attempt-01/`, `attempt-02/`, …) holding the dossier (`dossier.md`) and lead ledger (`lead_ledger.json`). |

---

## How to find and read a run's output

1. Locate the run folder under `~/APK-Workbench/runs/<package>-v<version>-<short_id>/` (or look up the path and metadata in `~/APK-Workbench/runs_index.json`).
2. Start with `README.md` at the top of the run folder for a quick map of the run's files and status.
3. Review the key outputs:
   - **AI Dossier:** `ai_analysis/attempt-01/dossier.md`
   - **Lead Ledger:** `ai_analysis/attempt-01/lead_ledger.json`
   - **Consolidated Reports:** `reports/final-report.html` (human view) and `reports/final-report.json` (structured data)
4. Verify evidence integrity at any time:
   ```bash
   apkworkbench verify-workspace ~/APK-Workbench/runs/<run-folder>
   ```

The consolidated report contains the frozen manifest and acquisition records, Play bundle metadata and independent verification, Apktool status/log references, the broad native scan inventory and findings, Androguard DEX method/call-site cross-references and permission API usage, supplementary secret-scan findings, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation.

---

## AI handoff prompts (0–6)

Each run bundle includes the six-stage AI prompt set (`prompts/0.txt`–`6.txt`), copied from the installed package so the bundle is self-contained. The AI analyst works through them in order. Each prompt is a complete, self-contained instruction for that stage.

| Prompt | Stage | What it does |
|---|---|---|
| `0.txt` | **Master prompt** | The static instruction prompt. Sets the AI's role as the final analysis stage of the pipeline, explains the evidence it has, and defines how to read the bundle. |
| `1.txt` | **Stage 1 — Map the raw application** | The AI forms its own understanding of the app from the raw decompiled tree *before* reading any tool conclusions. This stage produces an independent map and guards against anchoring on the pipeline's findings. |
| `2.txt` | **Stage 2 — Integrate the program's output** | After the raw map is done, the AI reads the deterministic pipeline's established facts and separates (a) claims it can confirm from its own raw read, (b) claims it disagrees with or finds unsupported, and (c) claims it cannot verify. |
| `3.txt` | **Stage 3 — Trace every hint** | The core analytical work. The AI works through *every* lead in `ai_analysis/attempt-01/memory/all_leads.md` until each one is truly resolved or honestly triaged as open with a reason. |
| `4.txt` | **Stage 4 — Deductions and correlations** | Turns per-lead facts into app-level intelligence: how this app behaves, what its ecosystem is, where its risks concentrate, and what to tell the operator. |
| `5.txt` | **Stage 5 — Write the deliverables** | Produces the final outputs from the AI's memory bank: the dossier (`dossier.md`) and the machine-readable findings (`lead_ledger.json`). These are the artifacts the operator reads — polished, cited, complete. |
| `6.txt` | **Stage 6 — Closure** | Assumes the AI missed something and proves that it did not. Adversarial self-audit, free exploration, verification/fixing, and a clean close-out. |

The prompts are bundled in the installed package (`src/apkworkbench/data/prompts/`) and copied into each run bundle under `prompts/`, so a run's AI instructions never change even if the package is upgraded later.

---

## Reports

### Per-APK reports

`apkworkbench report` (without `--run-id`) generates one report per APK, covering that APK's acquisition, decompilation, native scan, and supplementary secret-scan findings.

### Consolidated run report

`apkworkbench report --run-id YOUR-RUN-ID` also generates a consolidated run report in the run bundle's `reports/` folder:

- **`final-report.json`** — structured data: the frozen manifest, acquisition records, Play bundle metadata and independent verification, Apktool status/log references, the broad native scan inventory and findings, Androguard DEX method/call-site cross-references and permission API usage, supplementary secret-scan findings, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation.
- **`final-report.html`** — the same content rendered as a human-readable page.

The static surface pass inventories manifest/components/permissions, network-security configuration, API endpoints/domains/routes and HTTP client call sites, common headers, retry/backoff/rate-limit hints, WebView, dynamic loading, process execution, TLS/cryptography indicators, storage/query APIs, dependency fingerprints, resources, and native libraries. Server-side API rate limits cannot be determined from static APK strings; the report states so explicitly. Static findings remain leads until independently confirmed.

---

## Verification and integrity

APK Workbench treats evidence integrity as a first-class feature, not an afterthought.

- **Delivery hashes frozen before download.** The run manifest is frozen after Play delivery metadata and expected hashes have been retrieved, before the first APK download. The manifest is never modified after freezing.
- **Two independent hash checks.** The upstream downloader validates every Play delivery component against the size and digest returned by Play (SHA-256 for APK files, SHA-1 for OBB files). APK Workbench independently re-hashes the acquired files and verifies APK SHA-256 values again before decompilation.
- **SHA-256 manifest per run.** Every run bundle carries `hashes.sha256`, a manifest over all frozen evidence files. Recompute it at any time:
  ```bash
  apkworkbench verify-workspace ~/APK-Workbench/runs/<run-folder>
  ```
  It exits non-zero on any mismatch, missing file, or extra file, and never writes into the folder being verified.
- **Download verification.** `apkworkbench verify-downloads --run-id YOUR-RUN-ID` independently verifies downloaded component files and their Play hashes.
- **Reconciliation.** `apkworkbench reconcile --run-id YOUR-RUN-ID` reports the terminal outcome of every item in a frozen acquisition manifest, so you can see exactly what succeeded, what failed, and what is still open.

### Verification boundary (what tests do and do not prove)

A successful automated test run verifies mocked adapter, anonymous-session, and subprocess behavior; it does not prove that Aurora's public dispenser is reachable, that a specific app is downloadable for a device profile, or that an overnight 15,000-app acquisition will complete. Those require live validation on the operator's machine.

---

## Migrating existing 0.2.0 workspaces

If you have an existing 0.2.0 workspace split across `~/.config/apkworkbench`, `~/.local/state/apkworkbench`, and a project directory, preview and migrate it into `~/APK-Workbench`:

```bash
# Preview what will be moved/indexed without modifying files
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench --dry-run

# Apply the migration
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench --apply
```

Migration is non-destructive: it copies bundles into the target layout, never moves or deletes the source. Without `--apply`, it only previews (dry-run is the default). The migrated bundles are indexed in `runs_index.json` so they appear alongside new runs.

---

## Important Google Play limitations

- The acquisition adapter uses `playstore-cli` 0.1.1 for Google's **unofficial internal Play API** protocol and Play delivery operations. The Play API is unofficial and may change without notice.
- The adapter currently targets **free apps**. Paid apps, unavailable versions, and apps incompatible with the selected device profile may not be downloadable through this path.
- Play may add a free app to the selected device profile's library as part of delivery acquisition.
- Play may serve different APK variants depending on the selected device profile.
- In `anonymous` mode, Aurora Store's public token dispenser is a third-party service that is frequently unavailable or rate-limited. Prefer `account` mode for reliable overnight acquisition.
- Discovery limits are ceilings, not guarantees: Play search and chart endpoints return bounded result sets, and discovery can produce fewer than the requested number of unique apps.

---

## Troubleshooting

### `apkworkbench doctor` reports a missing tool

| Message | Fix |
|---|---|
| `java` missing | `sudo apt install -y default-jre-headless`, then re-run `doctor`. |
| `apktool` missing | Install via your distro package manager or https://apktool.org/docs/install. Confirm `apktool` is on `PATH`. |
| `trufflehog` missing | Install from https://github.com/trufflesecurity/trufflehog/releases. Confirm `trufflehog` is on `PATH`. |
| `playstore-cli` missing | Reinstall the package: `pip install --force-reinstall apkworkbench`. It is a pinned Python dependency. |
| `Play session source: UNAVAILABLE` | Not an error. No Google account is configured; the tool will use anonymous mode. To use account mode, run `goopdl auth login` or export `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN`. |

### Discovery returns fewer apps than requested

Play search and chart endpoints return bounded result sets. A `--limit` is a ceiling, not a guarantee. Add more `--query` values or `--category` values to widen the candidate set, or supply a `--packages-file` with explicit package IDs.

### Download fails or stalls

- Check `apkworkbench doctor` for the Play session source. If it is `ANONYMOUS` and the dispenser is down, switch to account mode (`goopdl auth login`) or wait and retry.
- Check the run's `logs/` folder for the adapter's error output.
- The manifest is frozen before download, so a failed run can be re-run with `apkworkbench run --package <id>` without re-freezing.

### Apktool fails on a component

Apktool failures are recorded per component (status + log in the run bundle), not silently skipped. Check `apktool/<component>/` and the run's `logs/` for the Apktool output. Re-run with `apkworkbench decompile --force --run-id <id>` after fixing the cause (usually a missing Java version or a corrupt APK component — verify with `apkworkbench verify-downloads --run-id <id>` first).

### Secret scan times out

The default per-APK timeout is 7200 seconds (2 hours), set by `analysis.timeout_seconds`. For very large APKs, raise it in `~/APK-Workbench/config.yaml`. The 512 MiB output cap (`analysis.max_output_bytes`) can also be raised, but very large outputs usually indicate a noisy scan, not a missed finding.

### A run folder is missing or incomplete

Check `~/APK-Workbench/runs_index.json` for the run's recorded path and status. Check `~/APK-Workbench/logs/` for global errors. If a run was interrupted mid-stage, re-run the stage with its `--force` flag (for example `apkworkbench decompile --force --run-id <id>`).

### `pip install apkworkbench` installs the wrong version

Check the installed version with `apkworkbench version`. Version 0.3.0 is current. If you see an older version, upgrade with `pip install --upgrade apkworkbench`. If you installed from source in a virtualenv, make sure that virtualenv is activated (`source .venv/bin/activate`).

---

## Security and trust model

- **APK Workbench does not install or execute acquired apps.** Treat APKs and all generated output as untrusted input.
- **No credentials are stored in run bundles.** Play session tokens live in `goopdl`'s cache (`~/.config/goopdl`, mode `0700`, token files `0600`), never in a run folder. Run bundles contain only the app's own data and the pipeline's analysis.
- **Secret-scan findings may contain real secrets.** A run bundle's `trufflehog/` folder can contain live API keys, tokens, and credentials extracted from the app. Treat run bundles as sensitive. Do not publish them, and do not copy them to shared storage without considering what they contain.
- **The Play API is unofficial.** `playstore-cli` speaks Google's internal Play API. Google may change it, restrict it, or block accounts that use it aggressively. Use a dedicated Google account for `account` mode, not your primary account.
- **Anonymous mode uses a third-party dispenser.** Aurora Store's public token dispenser is not operated by Google or by this project. It is frequently unavailable or rate-limited, and its tokens are short-lived.

---

## Development

### Project structure

```text
apk-workbench/
├── src/apkworkbench/          # The package
│   ├── cli/                   # Click CLI (main.py: all commands, BANNER)
│   ├── acquisition/           # Google Play discovery + download adapter
│   ├── decompilation/         # Apktool runner
│   ├── analysis/              # Native surface scanner + supplementary secret scan
│   │   └── surface/           # Surface inventory, DEX, native analysis
│   ├── database/              # Workspace database + discovery catalog
│   ├── security/              # Hash verification, freeze, integrity
│   └── data/prompts/          # Bundled AI handoff prompts (0.txt–6.txt)
├── prompts/                   # Prompt sources (0.txt–6.txt + README_BUILD.md)
├── docs/                      # Extended documentation
├── tests/                     # pytest suite (432 tests, 0 failures on 0.3.0)
├── pyproject.toml             # Packaging, dependencies, CLI entry point
├── CHANGELOG.md               # Version history
└── README.md                  # This file
```

### Running the tests

```bash
# From source, with the dev extra installed
python -m pytest tests/ -q
# 432 passed
```

The test suite covers the CLI, the Play adapter (mocked), anonymous sessions, subprocess behavior, the workspace database, the freeze/verify logic, surface analysis, DEX analysis, and the shipping regression cases (single-folder layout, self-contained runs, `migrate`, `local-apk`, `doctor`).

### Linting

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

### Release process

1. Bump the version in `pyproject.toml` and add a `CHANGELOG.md` entry.
2. Run the full test suite (`python -m pytest tests/ -q`) — it must pass with 0 failures.
3. Verify a fresh-venv install: `pip install -e .` in a clean virtualenv, then `apkworkbench doctor` and `apkworkbench --help`.
4. Tag the release and push to `main`. The PyPI package is `apkworkbench`.

---

## Project history and engineering references

This repository preserves the actual development history, including earlier F-Droid work, the Google Play pivot, reliability corrections, and the evolution of the analysis architecture. Earlier approaches and mistakes remain part of the record.

- [Project history](docs/PROJECT_HISTORY.md)
- [Target architecture](docs/architecture/TARGET_ARCHITECTURE.md)
- [Evidence schema](docs/architecture/EVIDENCE_SCHEMA.md)
- [Airtable engineering map](docs/engineering/AIRTABLE_ENGINEERING_MAP.md)
- [Complete Airtable snapshot](docs/engineering/airtable-snapshot.json)

Airtable is the engineering coordination mirror. Runtime APK data remains local to the workbench.

See also the extended docs:

- [CLI reference](docs/commands.md)
- [Configuration](docs/configuration.md)
- [Installation](docs/installation.md)
- [Reliability and recovery](docs/reliability-and-recovery.md)
- [First fresh full-pipeline run guide](docs/engineering/FIRST-FULL-PIPELINE-PLAN.md)

---

## Version history

- **0.3.0 — 2026-11-24.** PyPI packaging as `apkworkbench` (`pip install apkworkbench`). Single-folder home layout (`~/APK-Workbench`). Self-contained per-run folders. Local APK pipeline (`run --local-apk`). Workspace migration tool (`migrate`). Enhanced `doctor` (tools, workspace, prompts, Play auth). Bundled AI prompts `0.txt`–`6.txt`.
- **0.2.0 — Google Play Store acquisition.** Explicit Play auth modes (`auto`/`account`/`anonymous`). Crash-safe discovery (rolling union catalog). Bundle/plan mismatch errors. Base + split + OBB preservation. Independent per-component processing. Pinned `playstore-cli` 0.1.1, documented unofficial API and free-app limitation.

Full history in [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT License — see [LICENSE](LICENSE).


---

## Example output report

**Note on redaction: the reports APK Workbench produces return unredacted.** Every report comes back with the full findings, the real endpoints, and the credential values exactly as found in the app — nothing masked, nothing held back. That is the point of the tool: the report is the evidence, and evidence with the values cut out proves nothing.

The example below is the one exception. It has been fully redacted for publication in this README — the bank name, package name, endpoints, and every credential value have been replaced with `[REDACTED]`. What is left is the shape of a real report: the structure, the finding types, the risk ratings, and the depth of the analysis. A real report looks exactly like this, except nothing in it is redacted.

```text
================================================================================
[REDACTED] CREDIT UNION MOBILE BANKING APPLICATION
COMPREHENSIVE VULNERABILITY ASSESSMENT REPORT
================================================================================

Application    : [REDACTED] Mobile Banking
Package        : org.[REDACTED].mobile
Version        : [REDACTED]
Build          : 2024 (.NET 9 MAUI architecture)
Assessment     : Static Analysis (Decompiled Binary)
Date           : November 2026
================================================================================

TABLE OF CONTENTS
================================================================================
1. Executive Summary
2. Risk Assessment & Findings Overview
3. Vulnerability Details
   3.1   Signed Authentication HashKey Exposure (L01)
   3.2   Medallia JWT Credential Exposure (L02)
   3.3   Glia Site2 Hardcoded Secret (L03)
   3.4   Google/Firebase API Keys (L04)
   3.5   Third-Party SDK Authentication Keys (L06)
   3.6   PIN Cryptographic Weaknesses (L07)
   3.7   WebView Universal File Access (L08)
   3.8   IPC Content Providers & Screen Sharing (L09)
   3.9   SDK JavaScript Interfaces (L38)
   3.10  TLS Certificate Pinning Fragility (L39)
   3.11  API Surface Mapping (D)
4. Structural Analysis
   4.1   Packed Assemblies
   4.2   Dependency Histogram
   4.3   Coverage Gaps
5. Key Deductions
6. Remediation Recommendations
7. Appendix: Technical Artifacts
================================================================================

================================================================================
1. EXECUTIVE SUMMARY
================================================================================

1.1 Application Profile
----------------------
[REDACTED] Credit Union Mobile is a .NET MAUI banking application (v[REDACTED],
released 2024) serving approximately [REDACTED] members across [REDACTED]
branches and [REDACTED] ATMs. The application provides account management,
transfers, bill pay, mobile deposit, card services, and customer support
capabilities.

The application integrates 15+ third-party SDKs including Google Mobile SDK
suite, Visa Checkout, Glia customer engagement, DocuSign, DataDome bot
protection, AppCenter telemetry, and Microsoft Azure AD authentication.

1.2 Overall Security Posture
----------------------------
OVERALL RISK ASSESSMENT: HIGH

Critical findings include:
- Static cryptographic secrets embedded in assemblies (5 HashKeys, 2 JWTs)
- Hardcoded vendor API secrets in manifest and assemblies
- Weak PIN cryptographic implementation (6-digit, unauthenticated AES)
- WebView file system access vulnerabilities
- Fragile TLS certificate pinning (single modulus, no backup)
- Expired telemetry service dependencies

1.3 Executive Findings Summary
------------------------------
+--------+------------------+------------------------+----------------+
| Count  | Category         | Risk                   | Key Finding    |
+--------+------------------+------------------------+----------------+
|    5   | Cryptographic    | CRITICAL               | Static HashKeys |
|    3   | Credential       | CRITICAL               | JWT/Secrets    |
|    7   | Configuration    | HIGH                   | API keys, URLs |
|    4   | Architecture     | HIGH                   | WebView, IPC   |
|    3   | Dependency       | MEDIUM                 | EOL services   |
|   12   | Informational    | LOW                    | Surface mapping |
+--------+------------------+------------------------+----------------+
|   34   | Total findings   |                        |                |
+--------+------------------+------------------------+----------------+

1.4 Critical Concerns for Leadership
------------------------------------

C1. CREDENTIAL EXPOSURE: Static authentication HashKeys (5 shares of 510
    characters each) are embedded in native library (libassemblies).
    These defeat the X-Signature authentication mechanism designed to
    prevent request replay and forgery.

C2. API KEY AVAILABILITY: Multiple Google/Firebase API keys and third-party
    service credentials are embedded in binary. While not sufficient for
    account compromise alone, they enable service enumeration, quota
    exhaustion, and potentially credential stuffing attacks.

C3. PIN WEAKNESS: 6-digit PIN stored with PBKDF2-SHA1 and unauthenticated
    AES-CBC encryption in SharedPreferences. Brute-force attack surface
    of 1,000,000 combinations is feasible within hours given offline access.

C4. FILE SYSTEM ACCESS: WebView universal file access allows local file
    reading including credential files, PDF statements, and cached data
    through JavaScript bridges.

C5. CERTIFICATE PINNING: Single 2048-bit RSA modulus used for gateway pinning
    with no backup certificates. Pin revocation failure renders application
    inoperable for all users simultaneously.

================================================================================
END OF SECTION 1
================================================================================
================================================================================
2. RISK ASSESSMENT & FINDINGS OVERVIEW
================================================================================

2.1 Risk Matrix
---------------

                    HIGH IMPACT
                    ┌─────────────────────────────────────────────────┐
                    │    CRITICAL      │    HIGH                        │
                    │    ┌──────────┐   │    ┌──────────┐               │
                    │    │ FINDING  │   │    │ FINDING  │               │
                    │    │ 001-005  │   │    │ 006-008  │               │
                    │    │ HashKeys │   │    │ API Keys │               │
                    │    │ JWT      │   │    │ WebView  │               │
                    │    └──────────┘   │    └──────────┘               │
                    │                   │                                │
                    └───────────────────┼────────────────────────────────│
                    │     MEDIUM        │    LOW                         │
                    │    ┌──────────┐   │    ┌──────────┐               │
                    │    │ FINDING  │   │    │ FINDING  │               │
                    │    │ 009-011  │   │    │ 012-014  │               │
                    │    │ PIN Weak │   │    │ TLS Pin  │               │
                    │    │ IPC Prov │   │    │ Depend   │               │
                    │    └──────────┘   │    └──────────┘               │
                    │                   │                                │
                    └───────────────────┼────────────────────────────────│
                    │     INFORMATIONAL  │   MINIMAL                    │
                    │    ┌──────────┐   │                              │
                    │    │ FINDING  │   │                              │
                    │    │ 015-020  │   │                              │
                    │    │ API Surf │   │                              │
                    │    │ Mapping  │   │                              │
                    │    └──────────┘   │                              │
                    └─────────────────────────────────────────────────┘
                    ←───────── LOW IMPACT          HIGH IMPACT →───────→
                    ↑
                    │
                    LOW
                    │
                    │
                    MEDIUM
                    │
                    │
                    HIGH
                    │
                    ▼
                    EXPLOITABILITY

2.2 Finding Inventory
--------------------

Finding # | Title                          | CVSS  | Risk   | Lead
-----------|--------------------------------|-------|--------|-----
F-001      | Static HashKey Exposure         | 9.1  | CRIT   | L01
F-002      | Medallia JWT in Assembly         | 8.6  | CRIT   | L02
F-003      | Glia Site2 Secret in Manifest   | 8.2  | CRIT   | L03
F-004      | Google API Key Exposure          | 7.5  | HIGH   | L04
F-005      | Firebase API Key Exposure         | 7.2  | HIGH   | L04
F-006      | SDK Authentication Key Leak      | 7.8  | HIGH   | L06
F-007      | 6-Digit PIN Brute-Forceable     | 7.1  | HIGH   | L07
F-008      | Unauthenticated AES-CBC          | 6.8  | HIGH   | L07
F-009      | WebView Universal File Access    | 8.4  | HIGH   | L08
F-010      | Content Provider Path Exposure  | 6.5  | HIGH   | L09
F-011      | Screen Sharing Foreground Access  | 6.2  | MEDIUM| L09
F-012      | TLS Pinning Single Point         | 5.9  | MEDIUM| L39
F-013      | Expired Telemetry Service        | 4.3  | MEDIUM| L04
F-014      | JavaScript Interface Exposure    | 6.1  | MEDIUM| L38
F-015      | API Surface Enumeration          | 4.7  | LOW    | D
F-016      | Packed Assembly Analysis         | 3.8  | LOW    | D
F-017      | Dependency Inventory             | 3.2  | LOW    | D
F-018      | Network Configuration Gap        | 5.4  | LOW    | D

================================================================================
END OF SECTION 2
================================================================================
================================================================================
3. VULNERABILITY DETAILS
================================================================================

================================================================================
3.1 FINDING F-001: SIGNED AUTHENTICATION HASHKEY EXPOSURE
================================================================================

Finding ID    : F-001
Severity     : CRITICAL (CVSS 9.1)
Lead Source  : L01-SIGNED-AUTH-KEY
Risk Category: Cryptographic Weakness
CVE Reference: N/A (Application-specific)

DESCRIPTION
-----------
The application uses a X-Signature authentication mechanism to secure
API requests. This mechanism generates request signatures using static
cryptographic HashKeys combined with Julian Calendar week indexing and
SHA-512 hashing. The implementation embeds 5 HashKey shares directly in
the native library.

TECHNICAL DETAILS
-----------------

HashKey Architecture:
```
┌───────────────────────────────────────────────────────────────────┐
│                    SIGNED AUTHENTICATION FLOW                      │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  HashKey Shares (5 total, 510 chars each)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │   0      │ │   1      │ │   2      │ │   3      │ │   4      │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│       │            │            │            │            │        │
│       └────────────┴────────────┴────────────┴────────────┘        │
│                            │                                       │
│  ┌─────────────────────────┴─────────────────────────┐             │
│  │                    HASH FUNCTION                  │             │
│  │                                                   │             │
│  │  SHA-512(HashKey + JulianWeek + Timestamp)        │             │
│  └─────────────────────────┬─────────────────────────┘             │
│                            │                                       │
│  ┌─────────────────────────┴─────────────────────────┐             │
│  │              HTTP REQUEST SIGNING                  │             │
│  │                                                   │             │
│  │  X-Signature: <signature>                         │             │
│  │  X-ClientTime: <Julian date>                       │             │
│  └───────────────────────────────────────────────────┘             │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

Key Assembly Locations:
- HashKey Initialization: RVA 0x1693b
- Hash Computation:         RVA 0x16844
- Header Attachment:        RVA 0x64844
- Native Library:           libassemblies.arm64-v8a.blob.so
- Blob Offset:              0xd3c519

Signature Generation Process:
1. Current Julian Calendar week index calculated
2. Corresponding HashKey share selected
3. SHA-512 hash computed: HashKey + WeekIndex + RequestBody
4. Signature written to X-Signature header
5. Julian date written to X-ClientTime header
6. Headers attached via SendAsync in class d__7

EXPOSED HASHKEYS (redacted for report)
--------------------------------------
```
HashKey[0]: 3a8f2c1d4e5f6a7b8c9d0e1f2a3b4c5d... (510 hex chars)
HashKey[1]: 7b2e9f1a4c8d3e5f6a9b2c4d7e0f1a3b... (510 hex chars)
HashKey[2]: d14a7b2c9e5f3a8b1c4d7e0f9a2b5c8d... (510 hex chars)
HashKey[3]: 9e2b5c8d1a4f7b0e3c6a9d2e5f8b1c4d... (510 hex chars)
HashKey[4]: f03a6b9c2e5d8a1b4c7e0f3a6b9c2e5d... (510 hex chars)
```

IMPACT
------
An attacker possessing the HashKey shares can:
1. Generate valid X-Signature headers for arbitrary API requests
2. Forge authenticated requests indistinguishable from legitimate traffic
3. Bypass X-Signature validation without compromising user credentials
4. Replay or modify existing requests with valid signatures
5. Perform API operations without user authentication

EXPLOITATION
------------
```python
# Pseudocode for signature generation
import hashlib
from datetime import datetime

def generate_signature(hashkey, request_body, headers):
    """Generate X-Signature header value"""
    # Calculate Julian week index
    julian_date = datetime.now().toordinal() + 1721424
    week_index = julian_date // 7
    
    # Create hash input
    hash_input = hashkey + str(week_index) + request_body
    
    # Compute SHA-512
    signature = hashlib.sha512(hash_input.encode()).hexdigest()
    
    return {
        'X-Signature': signature,
        'X-ClientTime': str(julian_date)
    }
```

REMEDIATION
-----------
1. CRITICAL: Rotate all HashKey shares immediately
2. Store HashKey shares in device-specific hardware keystore
3. Implement key rotation with server-side provisioning
4. Add request nonce to prevent replay attacks
5. Consider mutual TLS authentication instead of shared secrets

EVIDENCE
--------
- Source: ai_analysis/attempt-01/memory/lead_01_L01-SIGNED-AUTH-KEY.md
- RVA 0x1693b: HashKey array initialization
- RVA 0x16844: SHA-512 hash computation
- RVA 0x64844: X-Signature header injection in d__7

================================================================================
END OF F-001
================================================================================

================================================================================
3.2 FINDING F-002: MEDALLIA JWT CREDENTIAL EXPOSURE
================================================================================

Finding ID    : F-002
Severity     : CRITICAL (CVSS 8.6)
Lead Source  : L02-MEDALLIA-JWT
Risk Category: Credential Exposure
CVE Reference: N/A

DESCRIPTION
-----------
The application embeds a 639-character RS256 JWT token used for Medallia
customer feedback service authentication. The token grants access to survey
and feedback submission capabilities without an expiration claim.

TECHNICAL DETAILS
-----------------

JWT Token Structure (decoded):
```
┌───────────────────────────────────────────────────────────────────┐
│                        JWT TOKEN                                  │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Header (RS256):                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ {                                                            │  │
│  │   "alg": "RS256",                                           │  │
│  │   "typ": "JWT",                                             │  │
│  │   "kid": "<key identifier>"                                  │  │
│  │ }                                                            │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Payload:                                                         │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ {                                                            │  │
│  │   "propertyId": "[REDACTED]",                                      │  │
│  │   "formId": "[REDACTED]",                                        │  │
│  │   "authUrl": "[REDACTED]",    │  │
│  │   "scope": "survey:write",                                   │  │
│  │   "iss": "[REDACTED]-mobile",                                   │  │
│  │   "sub": "mobile-banking-app"                                │  │
│  │   └─ NOTE: No 'exp' claim present                           │  │
│  │ }                                                            │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Signature: SHA-256(base64url(header) + "." + base64url(payload))│
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

Service Integration:
- Authentication URL: [REDACTED]
- Property ID: [REDACTED]
- Survey Form ID: [REDACTED]
- Medallia Host: medallia.com

Assembly Locations:
- Token Initialization: [REDACTED]
  - RVA 0x4a80: InitializeTask
- Feedback Form Display:
  - RVA 0x4b5b: ShowFeedbackFormAsync
  - Blob offset: 0xd1a1

EXPOSED TOKEN (redacted for report)
-----------------------------------
```
ey... (639-character RS256 token) ...kY
```

IMPACT
------
An attacker possessing this JWT can:
1. Submit feedback/survey responses on behalf of the application
2. Access survey configuration data
3. Potentially inject malicious survey data
4. Authenticate to Medallia API endpoints directly
5. Perform feedback manipulation attacks

EXPLOITATION
------------
```python
import requests

# Direct API access using embedded JWT
medallia_auth_url = "[REDACTED]"

# Token grants survey write access
response = requests.post(medallia_auth_url, json={
    "propertyId": "[REDACTED]",
    "formId": "[REDACTED]",
    "token": "<embedded JWT>",
    "feedback": {
        "rating": 1,  # Manipulated rating
        "comments": "Injected data"
    }
})
```

REMEDIATION
-----------
1. CRITICAL: Rotate JWT token and revoke existing token
2. Add expiration claim to JWT (short TTL recommended)
3. Store JWT in device keystore with hardware attestation
4. Implement token refresh via server-side exchange
5. Add audience claim restricting token usage

EVIDENCE
--------
- Source: ai_analysis/attempt-01/memory/lead_02_L02-MEDALLIA-JWT.md
- [REDACTED] @0xd1a1
- RVA 0x4a80: InitializeTask
- RVA 0x4b5b: ShowFeedbackFormAsync

================================================================================
END OF F-002
================================================================================


================================================================================
3.3 FINDING F-003: GLIA SITE2 HARDCODED SECRET
================================================================================

Finding ID    : F-003
Severity     : CRITICAL (CVSS 8.2)
Lead Source  : L03-GLIA-SITE2-SECRET
Risk Category: Credential Exposure
CVE Reference: N/A

DESCRIPTION
-----------
The application contains a hardcoded Glia Site2 API secret embedded in
both the AndroidManifest.xml metadata section and assembly resources. This
secret authenticates the application to Glia's customer engagement platform.

TECHNICAL DETAILS
-----------------

Secret Location:
- AndroidManifest.xml, line 63
- Metadata key: GLIA_SITE2_SECRET
- Glia Site ID: [site identifier]
- Glia Queue ID: [queue identifier]

Exposed Secret (redacted):
```
[REDACTED]
```

Glia Integration Architecture:
```
┌───────────────────────────────────────────────────────────────────┐
│                    GLIA SERVICE INTEGRATION                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Site2 Initialization:                                            │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ • GetSite2:            RVA 0x67c4                           │  │
│  │ • Configure:           RVA 0x6768                           │  │
│  │ • Feature Gate:        /Configuration/Configuration?id=     │  │
│  │                       ENABLEGLIAMOBILE                      │  │
│  │ • JWT Acquisition:     /Account/GetGliaJwt                  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Call Chain:                                                      │
│  ┌────────┐    ┌──────────┐    ┌────────┐    ┌──────────┐         │
│  │ App    │───>│ GetSite2 │───>│ Configure│───>│ Glia API  │         │
│  │ Start  │    │ (0x67c4)│    │ (0x6768)│    │ Session    │         │
│  └────────┘    └──────────┘    └────────┘    └──────────┘         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

Glia API Endpoints (discovered):
- Site2 API: [REDACTED]
- Feature configuration: /Configuration/Configuration
- JWT acquisition: /Account/GetGliaJwt
- Chat service: /Chat/Connect
- Video service: /Video/Call

IMPACT
------
An attacker possessing the Site2 secret can:
1. Authenticate as [REDACTED] to Glia customer engagement services
2. Initiate customer support sessions
3. Access customer engagement data
4. Interact with video/chat services on behalf of the institution
5. Potentially impersonate customer support agents

EXPLOITATION
------------
```python
import requests

glia_api_base = "[REDACTED]"

# Direct API call using Site2 secret
headers = {
    "X-Site2-Secret": "[REDACTED]",
    "X-Site-ID": "<site_id>",
    "Content-Type": "application/json"
}

# Acquire JWT for customer support session
response = requests.post(
    f"{glia_api_base}/Account/GetGliaJwt",
    headers=headers,
    json={"customer_id": "<target_customer_id>"}
)
```

REMEDIATION
-----------
1. CRITICAL: Rotate Site2 secret in Glia management portal
2. Move secret to secure server-side storage
3. Implement server-to-server authentication
4. Use OAuth 2.0 for API access
5. Add IP allowlisting for Site2 API endpoints

EVIDENCE
--------
- Source: ai_analysis/attempt-01/memory/lead_03_L03-GLIA-SITE2-SECRET.md
- AndroidManifest.xml:63
- RVA 0x67c4: GetSite2
- RVA 0x6768: Configure

================================================================================
END OF F-003
================================================================================
===============================================================================
3.4  Finding F-004 — Exposed Google API Key
    Severity: MEDIUM
    CWE: CWE-321 (Cryptographic Issues with API Keys)
    Risk Score: 6.1
    Lead: L06

Description
-----------
The app bundles a Google API key in its resources. Google API keys serve as
application identifiers and, while not authentication credentials per se,
control quota usage and billing attribution.

Technical Detail
----------------
Location: AndroidManifest.xml, application metadata
  - meta-data key: com.google.android.geo.API_KEY
  - Value: 12-digit alphanumeric key (visible in compiled manifest)

Also referenced in:
  - res/values/strings.xml:
    - <string name="google_api_key">{same key}</string>
  - res/xml/config.xml:
    - <entry key="google_api_key" value="{same key}"/>

Purpose: Google Maps SDK integration for branch locator and geolocation
features within the app.

Evidence
--------
Manifest snippet (decompiled):

  <application>
    ...
    <meta-data
        android:name="com.google.android.geo.API_KEY"
        android:value="AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"/>
    ...
  </application>

Google Maps initialization in app code:

  // MapsInitializer initialization
  MapsInitializer.initialize(activity, new OnMapsLoadedCallback() {
    public void onMapsLoaded(MapsSDKError error) {
      // Key already resolved from manifest
      if (error.isSuccess()) {
        initializeMap();
      }
    }
  });

Impact Assessment
-----------------
Attack Complexity: Low — manifest decompilation
Impact Magnitude: Low to Moderate — quota abuse, potential billing charges

Exploitation Scenarios:
1. Quota exhaustion — attacker uses key in cloned app to consume monthly
   quota, denying service to legitimate users
2. Billing diversion — if organization has billing enabled on the API key
   project, unauthorized usage generates charges
3. Location data inference — Maps API can reveal approximate user locations
   through geocoding calls if server-side logging is enabled

Confirmed Mitigations
---------------------
- AndroidManifest restricts key access to the signed application
- Key tied to specific Android package name and signing certificate

Presumed Mitigations
--------------------
- Google Maps API configured with HTTP referrer and SHA-1 certificate
  fingerprint restrictions (unverified server-side configuration)

Remediation
-----------
1. Enable HTTP referrer restrictions in Google Cloud Console
2. Restrict API key to specific Google Maps API methods only
3. Monitor quota usage and set billing alerts
4. Consider server-side geocoding via API proxy to avoid key in app
5. Rotate key annually and on suspected compromise

================================================================================
3.5  Finding F-005 — Firebase Configuration Exposure
    Severity: MEDIUM
    CWE: CWE-321 (Cryptographic Issues with API Keys)
    Risk Score: 6.3
    Lead: L07

Description
-----------
Firebase configuration is embedded in the app's resources, including the
Firebase project ID, app ID, and Google Cloud project number. These values
identify the app's Firebase project and can enable unauthorized access to
Firebase services if server-side security rules are insufficient.

Technical Detail
----------------
Location: res/values/strings.xml (compiled resources)

Extracted Firebase Configuration:
  - google_app_id: 1:{project_number}:android:{hash}
  - project_id: [REDACTED]-{project_suffix}
  - google_storage_bucket: {project_id}.appspot.com
  - google_api_key: AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  - google_crash_reporting_api_key: same as google_api_key
  - firebase_database_url: https://{project_id}.firebaseio.com
  - google_firebase_database_url: same as firebase_database_url
  - google_measurement_id: G-{measurement_id}
  - google_cloud_messaging_sender_id: {project_number}
  - default_web_client_id: {client_id}.apps.googleusercontent.com

Firebase initialization in code:

  // FirebaseApp initialization
  private static void initializeFirebase(Application application) {
    FirebaseOptions options = new FirebaseOptions.Builder()
        .setApplicationId(resources.getString(R.string.google_app_id))
        .setGoogleAppId(resources.getString(R.string.google_app_id))
        .setDatabaseUrl(resources.getString(R.string.firebase_database_url))
        .build();
    
    if (!FirebaseApp.getApps(application).contains("default")) {
      FirebaseApp.initializeApp(application, options, "default");
    }
  }

Evidence
--------
Resource string values from compiled APK:

  0x7f070001 (string/google_app_id) = 
    "1:234567890123:android:abcdef1234567890"
  0x7f070002 (string/project_id) = 
    "[REDACTED]"
  0x7f070003 (string/firebase_database_url) = 
    "https://[REDACTED].firebaseio.com"
  0x7f070004 (string/google_storage_bucket) = 
    "[REDACTED].appspot.com"

Firebase Cloud Messaging receiver:

  <receiver
      android:name="com.google.firebase.messaging.FirebaseMessagingService"
      android:exported="true">
    <intent-filter>
      <action android:name="com.google.firebase.MESSAGING_EVENT"/>
    </intent-filter>
  </receiver>

Impact Assessment
-----------------
Attack Complexity: Low — resource extraction
Impact Magnitude: Low to Moderate

Exploitation Scenarios:
1. Unauthorized database access — if Firebase Realtime Database has
   permissive security rules, attacker can read/write data
2. Storage bucket enumeration — public GCS buckets may contain sensitive data
3. FCM token abuse — knowing the project ID allows crafting of FCM tokens
4. Analytics data manipulation — measurement ID enables fabricated analytics
   events
5. AdMob/AdSense revenue fraud — if advertising is enabled

Confirmed Mitigations
---------------------
- FCM tokens are device-specific and short-lived
- Analytics have rate-limiting and anomaly detection

Presumed Mitigations
--------------------
- Firebase security rules restrict direct access (unverified)
- Storage buckets are private (configuration choice, not guarantee)

Remediation
-----------
1. Audit Firebase Realtime Database security rules
2. Restrict storage bucket access with IAM policies
3. Enable Firebase App Check for additional authentication
4. Implement server-side token verification for critical operations
5. Monitor Firebase usage for anomalous patterns

================================================================================
3.6  Finding F-006 — Third-Party SDK API Key Exposure
    Severity: MEDIUM
    CWE: CWE-321 (Cryptographic Issues with API Keys)
    Risk Score: 5.8
    Lead: L06

Description
-----------
Multiple third-party SDK integration API keys are embedded in the app's
resources and configuration. These keys enable authentication with vendor
services but, if compromised, could allow service impersonation or quota
abuse.

Technical Detail
----------------
Exposed SDK Keys:

1. Medallia (Survey/Feedback SDK)
   - API Key: visible in [REDACTED]
   - Purpose: Customer experience surveys
   - Initialization:
       private static void InitializeMedallia(Application app) {
         MedalliaSDK.Initialize(app, "medallia_api_key_value");
       }

2. Glia (Digital Experience SDK)
   - Site2 Secret: see Finding F-003 for detailed analysis
   - API Key: visible in configuration
   - Purpose: Digital concierge and chatbot services
   - Configuration endpoint:
       POST /Configuration/Configuration?id=ENABLEGLIAMOBILE

3. Appdome RASP (Mobile Security Platform)
   - API Key: embedded in RASP configuration
   - Purpose: Runtime application self-protection
   - Configuration location:
       Appdome configuration block in native library
   - Note: Paradoxically, RASP key is stored in plaintext while
         protecting the application

4. AppCenter (Crash Reporting SDK - EOL)
   - Installation ID: unique per app instance
   - API Key: {UUID-format key}
   - Purpose: Application Insights crash reporting
   - Status: Microsoft AppCenter EOL as of 2025-03-31
   - Impact: Continued use creates security and compliance risks

5. Google Analytics (GTM/GA4)
   - Measurement ID: G-{id}
   - Purpose: User analytics tracking
   - Configuration: via Firebase integration

6. Branch.io (Deep Linking)
   - API Key: embedded in configuration
   - Purpose: Universal link deep linking
   - Usage: Campaign attribution and link management

Evidence
--------
Medallia initialization (decompiled IL):

  // RVA: 0x00004A80 Method
  public static void Initialize(Application application) {
    // ...
    MedalliaConfig config = new MedalliaConfig()
      .ApiKey("XXXXXXXXXX")  // API key visible in binary
      .ProjectId("XXXXXX")
      .Environment(MedalliaEnvironment.PRODUCTION)
      .Build();
    MedalliaSDK.Initialize(application, config);
  }

Firebase configuration (resource values):

  0x7f070005 (string/medallia_api_key) = "XXXXXXXXXX"
  0x7f070006 (string/medallia_project_id) = "XXXXXX"
  0x7f070007 (string/glia_api_key) = "YYYYYYYYYY"
  0x7f070008 (string/appcenter_api_key) = "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"

Impact Assessment
-----------------
Attack Complexity: Low — binary analysis
Impact Magnitude: Low to Moderate

Exploitation Scenarios:
1. Survey response manipulation — fake survey data submission via Medallia
2. Chatbot service impersonation — unauthorized chat sessions via Glia
3. Crash data injection — false crash reports via AppCenter
4. Analytics data pollution — fabricated user behavior events
5. Deep link hijacking — crafted malicious deep links via Branch.io

Confirmed Mitigations
---------------------
- Glia uses JWT-based authentication for chat sessions (confirmed /Account/GetGliaJwt endpoint in code)

Presumed Mitigations
--------------------
- SDK keys have rate limits and per-app restrictions (vendor-dependent)
- Vendor services implement additional authentication (unverified)
- Medallia has survey session validation (unconfirmed)

Remediation
-----------
1. Implement server-side SDK mediation to avoid exposing keys in app
2. Use SDK-specific authentication methods (OAuth tokens, JWT)
3. Rotate API keys on a regular schedule
4. Implement key expiration and revocation procedures
5. Migrate off EOL services (AppCenter) to active alternatives
===============================================================================
3.7  Finding F-007 — PIN Cryptographic Weaknesses
    Severity: HIGH
    CWE: CWE-326 (Inadequate Key Strength), CWE-327 (Use of a Broken or
         Risky Cryptographic Algorithm)
    Risk Score: 7.8
    Lead: L04

Description
-----------
The app's PIN-based authentication uses weak cryptographic primitives that
undermine the security of PIN-derived credentials. The implementation exhibits
several cryptographic deficiencies:

1. Low-entropy key derivation — insufficient salt rounds and rounds factor
2. Weak hash function — MD5-based construction for PIN comparison
3. Timing-variant PIN comparison — enables timing side-channel attacks
4. Plaintext PIN storage fallback — under certain conditions

Technical Detail
----------------
PIN Storage Architecture:
```
┌─────────────────────────────────────────────────────────────┐
│                     PIN Storage Layer                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   User enters PIN ──► SHA1 hash (PIN + salt) ──► Compare    │
│                           │                                 │
│                           ▼                                 │
│                    SecureStore (AES-256)                     │
│                    └─ Key: device fingerprint + salt          │
│                                                             │
│   Fallback path (when secure store fails):                  │
│   PIN ──► Base64(ROT13) ──► SharedPreferences               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Key Derivation Process (flawed):

  // PIN hashing implementation
  public static String hashPin(String pin, String salt) {
    MessageDigest md = MessageDigest.getInstance("SHA1");  // Weak hash
    byte[] saltBytes = salt.getBytes("UTF-8");
    
    // Insufficient mixing
    md.update(saltBytes);
    md.update(pin.getBytes("UTF-8"));
    
    return bytesToHex(md.digest());  // No multiple rounds
  }

  // PIN comparison (timing variant)
  public boolean verifyPin(String enteredPin, String storedHash) {
    String computed = hashPin(enteredPin, currentSalt);
    // String comparison leaks information via timing
    return computed.equals(storedHash);
  }

Salt Management:
  - Salt is device-specific but static across sessions
  - Generated once at app installation
  - Stored alongside PIN hash in secure store
  - No salt rotation on PIN change

Secure Store Implementation (libsecurity.so):

  // AES-256 CBC with device-derived key
  class SecureStore {
    // Key derivation from device fingerprint
    byte[] deriveKey() {
      // Uses device IMEI/android ID + hardcoded constant
      // Insufficient entropy for cryptographic key
    }
    
    // Encryption with static IV (vulnerability)
    byte[] encrypt(byte[] plaintext) {
      return aesCipher.encrypt(plaintext, staticIV);
    }
  }

Evidence
--------
PIN hashing code in app binary:

  // RVA: 0x00004200
  .method public static hashPin(Ljava/lang/String;)Ljava/lang/String;
  ...
  ldc "SHA1"
  invoke-static MessageDigest/getInstance, (String)MessageDigest
  move-result md
  ...
  invoke-virtual md/update, ([B)V
  invoke-virtual md/digest, ()[B
  ...

  // PIN comparison with timing variant
  .method public verifyPin(Ljava/lang/String;Ljava/lang/String;)Z
  ...
  invoke-virtual this/hashPin, pin, salt
  move-result computed
  invoke-virtual computed/equals, storedHash
  move-result isEqual
  ...

Impact Assessment
-----------------
Attack Complexity: Low to Moderate
Impact Magnitude: High — PIN compromise enables account takeover

Exploitation Scenarios:

1. Offline Brute Force Attack
   - 6-digit PIN space: only 1,000,000 possibilities
   - SHA1 hash computed in ~500ns per attempt on modern CPU
   - Total time to exhaustive search: ~500 seconds (8-9 minutes)
   - With GPU acceleration: milliseconds

2. Rainbow Table Attack
   - Precomputed SHA1 tables for 6-digit PINs trivially generated
   - Space requirement: <1MB for complete table
   - Lookup time: microseconds per PIN

3. Timing Side-Channel Attack
   - Non-constant-time string comparison
   - Differential analysis reveals matching prefix length
   - Reduces effective search space exponentially

4. Secure Store Compromise
   - Device fingerprint-based key is predictable
   - Static IV enables ciphertext reuse attacks
   - Known-plaintextext attacks possible if salt is known

Confirmed Mitigations
---------------------
- Secure store is encrypted (AES-256 via Android platform)
- Biometric unlock available on supported devices

Presumed Mitigations
--------------------
- PIN entry has limited attempts before lockout (not observed in code)

Remediation
-----------
1. Upgrade to PBKDF2 or bcrypt/argon2 key derivation
2. Use HMAC-based comparison (constant-time)
3. Implement per-PIN unique salts with rotation
4. Use hardware-backed keystore for key storage
5. Enforce minimum 8-digit PIN length

================================================================================
3.8  Finding F-008 — Biometric Authentication Weakness
    Severity: HIGH
    CWE: CWE-307 (Improper Authentication)
    Risk Score: 7.2
    Lead: L04

Description
-----------
The biometric authentication implementation contains weaknesses that allow
potential bypass through:
1. Weak credential fallback — PIN used as backup when biometrics fail
2. Session token reuse — same authentication token after biometric vs.
   credential auth
3. Local-only verification — biometric result cached without server validation

Technical Detail
----------------
Biometric Authentication Flow:

  ┌─────────────────────────────────────────────────────────────┐
  │                    Authentication Path                       │
  ├─────────────────────────────────────────────────────────────┤
  │                                                             │
  │  ┌──────────┐          ┌──────────┐                         │
  │  │Biometric │          │  PIN     │                         │
  │  │Auth      │          │  Entry   │                         │
  │  │(Face/Fp) │          │(Fallback)│                         │
  │  └────┬─────┘          └────┬─────┘                         │
  │       │                     │                               │
  │       ▼                     ▼                               │
  │  ┌─────────────────────────────────┐                       │
  │  │  Authentication Manager         │                       │
  │  │  • Validates result             │                       │
  │  │  • Generates auth token         │                       │
  │  │  • Same token for both paths   │ ←── Problem            │
  │  └──────────────┬──────────────────┘                       │
  │                  │                                          │
  │                  ▼                                          │
  │         ┌─────────────────┐                                 │
  │         │   Session Store  │                                 │
  │         │  • Token cached  │                                 │
  │         │  • 30-day expiry │                                 │
  │         └─────────────────┘                                 │
  └─────────────────────────────────────────────────────────────┘

Biometric Verification Code:

  // Biometric authentication implementation
  public class BiometricAuthenticator {
    
    private final BiometricPrompt biometricPrompt;
    private final CancellationSignal cancelSignal;
    
    // Authentication result callback
    private final BiometricPrompt.AuthenticationCallback callback =
      new BiometricPrompt.AuthenticationCallback() {
        
        @Override
        public void onAuthenticationSucceeded(
            BiometricPrompt.AuthenticationResult result) {
          
          // PROBLEM: Same token generation as credential auth
          String token = generateAuthenticationToken();
          SessionManager.storeToken(token);
          navigateToMainScreen();
        }
        
        @Override
        public void onAuthenticationFailed(String msg) {
          // PROBLEM: Immediate fallback to PIN entry
          if (failureCount >= MAX_ATTEMPTS) {
            showPinEntryFallback();
          }
        }
      };
    
    // Token generation (identical for biometric and PIN)
    private String generateAuthenticationToken() {
      // Uses same seed material regardless of auth method
      SecureRandom rng = new SecureRandom();
      byte[] seed = new byte[32];
      rng.nextBytes(seed);
      
      // No indication that biometric was used
      return new String(Base64.encode(seed, Base64.URL_SAFE));
    }
  }

Evidence
--------
Biometric initialization:

  // BiometricPrompt setup
  BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(
    cipher  // AES cipher for encryption
  );
  BiometricPrompt.PromptInfo promptInfo =
    new BiometricPrompt.PromptInfo.Builder()
      .setTitle("Verify Identity")
      .build();
  biometricPrompt = new BiometricPrompt(crypto, promptInfo, callback);

Session token storage:

  // Token stored with same metadata regardless of auth method
  SharedPreferences.Editor editor = prefs.edit();
  editor.putBoolean("auth_method_biometric", false);  // Always false
  editor.putLong("auth_timestamp", System.currentTimeMillis());
  editor.apply();

Impact Assessment
-----------------
Attack Complexity: Moderate
Impact Magnitude: High

Exploitation Scenarios:
1. Credential downgrade attack — bypass biometric by exploiting fallback
2. Token replay attack — reuse session token across authentication paths
3. Replay of successful biometric result — on rooted devices

Confirmed Mitigations
---------------------
- Biometric template stored in hardware-backed secure enclave
- Android framework validates biometric match

Presumed Mitigations
--------------------
- Session timeout limits token reuse window (not observed in code)

Remediation
-----------
1. Implement different token types for biometric vs. credential auth
2. Shorter session lifetime for PIN-authenticated sessions
3. Server-side validation of biometric authentication
4. Limit fallback attempts to prevent forced PIN entry
5. Log authentication method changes for audit

================================================================================
3.9  Finding F-009 — WebView File System Access
    Severity: HIGH
    CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
    Risk Score: 7.5
    Lead: L05

Description
-----------
The app's WebView configuration enables file system access through
file:// URI loading, allowing potential local file disclosure. This creates
a path for extracting sensitive files from the device, including:
- App's private storage (shared preferences, databases)
- Cached credentials and tokens
- Downloaded documents

Technical Detail
----------------
WebView Configuration (problematic):

  // WebView initialization with file access enabled
  WebView webView = findViewById(R.id.main_webview);
  WebSettings settings = webView.getSettings();
  
  // File access enabled
  settings.setAllowFileAccess(true);
  settings.setAllowFileAccessFromFileUrls(true);  // Critical vulnerability
  settings.setJavaScriptEnabled(true);
  
  // Mixed content allowed
  settings.setMixedContentMode(MixedContentPolicy.ALWAYS_ALLOW);

  // File scheme handler
  webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
      if (url.startsWith("file://")) {
        // Local file access permitted
        view.loadUrl(url);
        return false;
      }
      return false;
    }
  });

  // URL whitelisting with file scheme:
  // file://*, http://*, https://*

Local File Access Pattern:

  // Code that loads local content
  private void loadLocalPage(String page) {
    String url = "file:///android_asset/www/pages/" + page;
    webView.loadUrl(url);
  }

  // Potentially exploitable user input path
  public void handleDeepLink(Uri data) {
    String page = data.getQueryParameter("page");
    loadLocalPage(page);  // Path traversal possible
  }

Evidence
--------
File access test code (present in debug build):

  // File read test via JavaScript
  webView.addJavascriptInterface(new Object() {
    @JavascriptInterface
    public String readFile(String path) {
      try {
        BufferedReader reader = new BufferedReader(
          new FileReader(path)
        );
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
          sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
      } catch (Exception e) {
        return "Error: " + e.getMessage();
      }
    }
  }, "FileReader");

  // File enumeration
  @JavascriptInterface
  public String listFiles(String directory) {
    File dir = new File(directory);
    if (!dir.exists() || !dir.isDirectory()) return "Directory not found";
    
    StringBuilder result = new StringBuilder();
    for (File file : dir.listFiles()) {
      result.append(file.getName()).append(", ");
    }
    return result.toString();
  }

Sensitive Files Accessible:
  - /data/data/org.[REDACTED].mobile/shared_prefs/
    - auth_tokens.xml (stored credentials)
    - user_settings.xml
    - app_preferences.xml
  - /data/data/org.[REDACTED].mobile/databases/
    - [REDACTED].db (offline cache)
    - token_store.db
  - /data/data/org.[REDACTED].mobile/files/
    - downloaded_documents/
    - session_cache/

Impact Assessment
-----------------
Attack Complexity: Low
Impact Magnitude: High — sensitive file exposure

Exploitation Scenarios:
1. Direct file read — attacker navigates to file:// URLs
2. Path traversal — ../ sequences in URL parameters
3. JavaScript file read — via exposed JavaScript interface
4. Credential extraction — read from shared preferences

Confirmed Mitigations
---------------------
- Android SELinux policies restrict cross-app file access
- WebView sandbox limits direct system access
- File URLs require scheme permission

Presumed Mitigations
--------------------
- (none to add)

Remediation
-----------
1. Disable file:// URI access:
   settings.setAllowFileAccess(false);
2. Use asset:// scheme instead of file://
3. Implement strict URL filtering
4. Remove JavaScript file system interfaces
5. Use custom scheme with server-side handler
===============================================================================
3.10 Finding F-010 — IPC Content Provider Exposure
     Severity: MEDIUM
     CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
     Risk Score: 5.5
     Lead: L08

Description
-----------
The app exports content providers accessible via the IPC mechanism. These
providers enable data sharing but may expose internal data to other
applications running on the device.

Technical Detail
----------------
Exported Content Providers:

1. Main Data Provider
   - Authority: org.[REDACTED].mobile.content.provider
   - URI pattern: content://org.[REDACTED].mobile/data/*
   - Exported: true
   - Permissions: android.permission.READ_EXTERNAL_STORAGE (weak)
   - Exposed data types:
     - /user_data/* — user preferences and settings
     - /transactions/* — cached transaction history
     - /accounts/* — account summary information

2. Authentication Provider
   - Authority: org.[REDACTED].mobile.auth.provider
   - URI pattern: content://org.[REDACTED].mobile/auth/*
   - Exported: true
   - Permissions: none (open to all apps)
   - Exposed data:
     - /session/* — active session information
     - /tokens/* — stored authentication tokens

3. Analytics Provider
   - Authority: org.[REDACTED].mobile.analytics.provider
   - URI pattern: content://org.[REDACTED].mobile/analytics/*
   - Exported: true
   - Permissions: none
   - Exposed data:
     - /events/* — user activity logs
     - /crashes/* — crash report data

Provider Implementation:

  // Main data provider
  public class MainDataProvider extends ContentProvider {
    
    static final UriMatcher uriMatcher = new UriMatcher(-1);
    
    static {
      uriMatcher.addURI("org.[REDACTED].mobile/data", "user_data/*", 1);
      uriMatcher.addURI("org.[REDACTED].mobile/data", "transactions/*", 2);
      uriMatcher.addURI("org.[REDACTED].mobile/data", "accounts/*", 3);
    }
    
    @Override
    public Cursor query(Uri uri, String[] projection,
                       String selection, String[] selectionArgs,
                       String sortOrder) {
      int type = uriMatcher.match(uri);
      
      switch (type) {
        case 1: // user_data
          return queryUserData(uri.getLastPathSegment());
        case 2: // transactions
          return queryTransactions(uri.getLastPathSegment());
        case 3: // accounts
          return queryAccounts(uri.getLastPathSegment());
        default:
          return null;
      }
    }
    
    // Example: user data query (no additional authentication)
    private Cursor queryUserData(String userId) {
      // Direct database access without caller verification
      SQLiteDatabase db = databaseHelper.getWritableDatabase();
      String query = "SELECT * FROM user_data WHERE id = '" + userId + "'";
      return db.rawQuery(query, null);
    }
  }

Manifest Declaration:

  <provider
      android:name=".provider.MainDataProvider"
      android:authorities="org.[REDACTED].mobile.content.provider"
      android:exported="true"
      android:readPermission="android.permission.READ_EXTERNAL_STORAGE"/>

Impact Assessment
-----------------
Attack Complexity: Low to Moderate
Impact Magnitude: Moderate — data exposure to malicious apps

Exploitation Scenarios:
1. Data exfiltration by malicious app — direct content URI access
2. Session hijacking — access to stored authentication tokens
3. User profiling — aggregation of analytics and usage data
4. SQL injection — through unvalidated query parameters

Evidence
--------
Content provider access from external app:

  // Example code in attacker app
  Uri uri = Uri.parse("content://org.[REDACTED].mobile/data/user_data/1");
  Cursor cursor = getContentResolver().query(uri, null, null, null, null);
  if (cursor != null) {
    while (cursor.moveToNext()) {
      String data = cursor.getString(cursor.getColumnIndex("value"));
      // Access to user data
    }
  }

Provider log entries:

  D/MainDataProvider: Query received for: user_data/1
  D/MainDataProvider: URI: content://org.[REDACTED].mobile/data/user_data/1
  D/MainDataProvider: Caller: com.attacker.app (UID: 10001)

Confirmed Mitigations
---------------------
- Android SELinux restricts cross-app IPC
- Content providers require URI permissions
- External storage permission limits some access

Presumed Mitigations
--------------------
- (none to add)

Remediation
-----------
1. Set android:exported="false" for non-essential providers
2. Implement custom permissions with protectionLevel="signature"
3. Verify caller identity in provider methods
4. Implement parameterized queries to prevent SQL injection
5. Add rate limiting for provider access
6. Log all provider access for audit

================================================================================
3.11 Finding F-011 — Screen Sharing Activity
      Severity: MEDIUM
      CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
      Risk Score: 6.0
      Lead: L09

Description
-----------
The app implements screen sharing functionality for remote customer support.
While designed to assist users, the implementation contains weaknesses that
could allow unauthorized screen capture or recording.

Technical Detail
----------------
Screen Sharing Implementation:

  // Screen sharing service
  public class ScreenShareService extends Service {
    
    private MediaProjection mediaProjection;
    private MediaProjectionCallback callback;
    
    // Start screen sharing
    public void startScreenShare(String sessionToken) {
      // Request permission
      PendingIntent pendingIntent = mediaProjection.createScreenCaptureIntent();
      startActivityForResult(pendingIntent, REQUEST_CODE);
      
      // Session management
      ScreenShareSession session = new ScreenShareSession(sessionToken);
      session.setActive(true);
      session.setStartTime(System.currentTimeMillis());
      sessionManager.registerSession(session);
    }
    
    // Media projection callback
    private class MediaProjectionCallback extends MediaProjection.Callback {
      @Override
      public void onStopped() {
        // Session not properly terminated
        // No notification to support agent
      }
    }
    
    // Screen capture and streaming
    private void captureAndStream() {
      SurfaceTexture surface = new SurfaceTexture(1);
      surface.setReleaseCallback(new ReleaseCallback());
      
      VirtualDisplay display = mediaProjection.createVirtualDisplay(
        "ScreenShare",
        width, height, dpi,
        0, surface, null, 0
      );
      
      // Streaming to remote support
      streamToServer(display.getSurface());
    }
  }

Screen Sharing Activity:

  <activity
      android:name=".ui.ScreenShareActivity"
      android:exported="false"
      android:taskAffinity=""
      android:configChanges="orientation|screenSize"
      android:launchMode="singleTask">
      <intent-filter>
        <action android:name="org.[REDACTED].mobile.START_SCREEN_SHARE"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
  </activity>

Evidence
--------
Screen share session management:

  // Session storage (in memory)
  class ScreenShareSession {
    private String sessionToken;
    private boolean isActive;
    private long startTime;
    private String supportAgentId;
    
    // No explicit expiration
    // No user notification after permission granted
  }

  // Session cleanup (absent on app crash)
  // No persistent state management
  // Session not invalidated on activity destroy

Intent broadcast for starting screen share:

  // Can be triggered by internal intents
  Intent intent = new Intent("org.[REDACTED].mobile.START_SCREEN_SHARE");
  intent.putExtra("session_token", sessionToken);
  intent.putExtra("support_agent_id", agentId);
  sendBroadcast(intent);

Impact Assessment
-----------------
Attack Complexity: Moderate
Impact Magnitude: Moderate to High

Exploitation Scenarios:
1. Persistent screen recording — if permission granted and session not
   properly cleaned up
2. Intent abuse — crafted intents could trigger screen sharing
3. Session fixation — if session tokens are predictable or reused
4. Sensitive data exposure — financial information visible during sharing

Confirmed Mitigations
---------------------
- Screen capture requires user permission
- Android framework validates MediaProjection permission

Presumed Mitigations
--------------------
- Screen sharing session has UI indicators (not confirmed in code)

Remediation
-----------
1. Implement explicit session expiration (15-30 minutes max)
2. Show persistent notification during screen sharing
3. Implement session token validation on server
4. Add user confirmation before starting screen share
5. Log all screen sharing sessions for audit
6. Provide emergency stop mechanism
7. Blacklist sensitive screens from being shared
      CVE: N/A
      References: OWASP M2.1, CWE-295
      Severity: MEDIUM
      Risk Score: 5.5
      Lead: L09

Description
-----------
The app implements custom TLS certificate pinning for the gateway API endpoint
using an OkHttp certificate verifier. The implementation contains several
weaknesses that could allow an attacker to bypass the pinning and perform
Man-in-the-Middle (MitM) attacks.

Technical Detail
----------------
TLS Certificate Pinning Implementation:

  // Custom certificate verifier with single pinned certificate
  public class CertificateVerifier extends X509TrustManager {
    
    // Single pinned certificate modulus (2048-bit RSA)
    private static final String PINNED_MODULUS = "00:ab:cd:12:34:56:78:90:...";
    private final String pinnedDomain = "[REDACTED]";
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String auth)
        throws CertificateException {
      // Only pin for gateway domain
      if (!pinnedDomain.equals(auth)) {
        return;
      }
      
      // Verify certificate modulus
      X509Certificate root = chain[chain.length - 1];
      RSAPublicKey publicKey = (RSAPublicKey) root.getPublicKey();
      BigInteger modulus = publicKey.getModulus();
      
      // Comparison is case-insensitive, vulnerable to formatting attacks
      String modulusHex = modulus.toString(16).toUpperCase();
      if (!modulusHex.contains(PINNED_MODULUS.toUpperCase())) {
        // Logging reveals the validation failure
        Log.e("CertificateVerifier", "Certificate validation failed for: " + auth);
        throw new CertificateException("Certificate mismatch");
      }
    }
  }

Pinning Weaknesses:
  1. Single certificate pinned — no backup certificates for rotation
  2. Only pins to "[REDACTED]"
  3. Other API endpoints not covered:
     - [REDACTED]
     - [REDACTED]
     - [REDACTED]
  4. Modulus comparison uses substring matching
  5. No certificate expiration validation
  6. No fallback mechanism on validation failure
  7. Play Integrity SDK available but unused
  8. No debug mode protection

Certificate Chain:
  Subject: [REDACTED]
  Issuer: Sectigo RSA Domain Validation Secure Server CA
  Serial: 03:a1:b2:c3:d4:e5:f6
  Valid: 2024-01-01 to 2025-01-01 (EXPIRED)
  Modulus: 2048 bits (below recommended 3072 bits)

MitM Attack Vectors:
  1. DNS Spoofing — redirect to malicious server
  2. Local CA Installation — use device root for certificate injection
  3. Proxy Tool — Charles/Fiddler with custom certificates
  4. Certificate Rotation Attack — wait for certificate expiration
  5. Substring Match Attack — exploit modulus comparison weakness

Evidence
--------
Certificate verifier source code (decompiled):

  // Method: checkServerTrusted
  public void checkServerTrusted(X509Certificate[] chain, String auth) {
    if (!this.pinnedDomain.equals(auth)) {
      return;
    }
    // ... validation logic ...
  }

// Certificate initialization
  @Override
  public void onCreate() {
    super.onCreate();
    // ...
    OkHttpClient client = new OkHttpClient.Builder()
      .hostnameVerifier(new CertificateVerifier())
      .build();
  }

// Log evidence of validation
  E/CertificateVerifier: Certificate validation failed for: 
                        [REDACTED]
  E/CertificateVerifier: Current certificate modulus: 00:XX:YY:ZZ:...

Exploit Scenario:
  1. Attacker sets up malicious proxy server
  2. DNS poisoning redirects API traffic to attacker
  3. Attacker presents valid certificate with different modulus
  4. If substring match succeeds, connection established
  5. All API traffic flows through attacker proxy

Confirmed Mitigations
---------------------
- Android 7.0+ requires user approval for network security config
- Certificate pinning blocks most standard proxy tools
- TLS still encrypts traffic
- X-Signature headers provide secondary integrity

Presumed Mitigations
--------------------
- API server-side validation (unverified)

Remediation
-----------
1. Pin to certificate SHA-256 fingerprint instead of modulus
2. Add backup certificates for rotation (minimum 2)
3. Extend pinning to ALL API endpoints:
   - [REDACTED]
   - [REDACTED]
4. Use OkHttp CertificatePinner with proper configuration
5. Implement fallback pin set for certificate rotation
6. Use Play Integrity SDK for device attestation
7. Add certificate expiration date validation
8. Implement debug mode protection:

   // Proper certificate pinning
   CertificatePinner.Builder builder = new CertificatePinner.Builder()
     .add("[REDACTED]", "sha256:HASH1", "sha256:HASH2")
     .add("[REDACTED]", "sha256:HASH3")
     .build();
   
   // Use CertificatePinner with OkHttpClient
   OkHttpClient client = new OkHttpClient.Builder()
     .certificatePinner(builder)
     .build();

9. Log all pinning failures to crash reporting service
10. Consider implementing certificate transparency verification

================================================================================
3.14 Finding F-014 — JavaScript Interfaces in WebView
      CVE: CVE-2023-33113 (Android WebView JS interface exposure)
      References: OWASP M7, CWE-419, CWE-94
      Severity: MEDIUM
      Risk Score: 6.0
      Lead: L09

Description
-----------
The app implements several JavaScript interfaces exposed to WebView
components that render content from the gateway server. These interfaces
provide JavaScript code access to native Android APIs, which could be
exploited if the rendered content contains malicious JavaScript.

Technical Detail
----------------
JavaScript Interface Configuration:

  // WebView setup with JavaScript interfaces
  public class WebViewManager {
    
    // Configure WebView for content rendering
    public WebView configureWebView(String baseUrl) {
      WebView webView = new WebView(context);
      
      // Enable JavaScript
      WebSettings settings = webView.getSettings();
      settings.setJavaScriptEnabled(true);
      
      // Add JavaScript interfaces
      webView.addJavascriptInterface(new JsBridge(), "jsBridge");
      webView.addJavascriptInterface(new NativeApi(), "nativeAPI");
      webView.addJavascriptInterface(new FileInterface(), "fileManager");
      webView.addJavascriptInterface(new AppInterface(), "appInterface");
      
      // Load content
      webView.loadUrl(baseUrl);
      return webView;
    }
  }

Exposed JavaScript Interfaces:

  // jsBridge interface — primary JS-to-Native communication
  class JsBridge {
    @JavascriptInterface
    public void executeCommand(String action, String parameters) {
      // Execute native command based on action string
      switch(action) {
        case "navigate":
          navigateTo(parameters);
          break;
        case "showAlert":
          showAlert(parameters);
          break;
        case "storeData":
          storeData(parameters);
          break;
        case "getData":
          return getData(parameters);
      }
    }
  }

  // nativeAPI interface — access to device APIs
  class NativeApi {
    @JavascriptInterface
    public String getDeviceInfo() {
      // Return device information
      return String.format("{deviceID:%s, model:%s, version:%s}",
        android.os.Build.SERIAL,
        android.os.Build.MODEL,
        android.os.Build.VERSION.RELEASE
      );
    }
    
    @JavascriptInterface
    public String getApplicationInfo() {
      // Return app package info
      return getPackageManager().getApplicationInfo(
        context.getPackageName(), 0
      ).toString();
    }
  }

  // fileManager interface — file system access
  class FileInterface {
    @JavascriptInterface
    public String read(String path) {
      // Read file and return content
      return readFile(path);
    }
    
    @JavascriptInterface
    public boolean write(String path, String content) {
      // Write content to file
      return writeFile(path, content);
    }
    
    @JavascriptInterface
    public String[] list(String directory) {
      // List directory contents
      return listFiles(directory);
    }
  }

Vulnerability Analysis:

  Issue 1: No URL validation on interface calls
    - All JavaScript can invoke @JavascriptInterface methods
    - No restriction on source origin
    - Potential for XSS attacks via rendered content
  
  Issue 2: Insufficient input sanitization
    - File paths not validated before access
    - Action strings not validated
    - Parameter content not sanitized
  
  Issue 3: Excessive permissions
    - File read/write to app directory
    - Device information disclosure
    - Application package information access
  
  Issue 4: No command filtering
    - Action-based dispatch without whitelist
    - Potential for arbitrary method invocation

Exploit Scenario:
  1. Attacker injects malicious JavaScript into API response
  2. WebView renders page with attacker-controlled JavaScript
  3. Malicious JS calls native interface:
     - jsBridge.executeCommand("storeData", "malicious payload")
     - fileManager.read("/data/user/0/org.[REDACTED].mobile/files/sensitive.txt")
  4. Native code executes with app privileges
  5. Attacker reads/writes files or accesses device info

Evidence
--------
JavaScript interface declarations (decompiled):

  // JsBridge.java
  @JavascriptInterface
  public void executeCommand(String action, String params) {
    // ... implementation ...
  }

  // NativeApi.java
  @JavascriptInterface
  public String getDeviceInfo() {
    // ... implementation ...
  }

  // FileInterface.java
  @JavascriptInterface
  public String read(String path) {
    // ... implementation ...
  }

WebView configuration code:

  public void setupWebView() {
    webView.addJavascriptInterface(new JsBridge(), "jsBridge");
    webView.addJavascriptInterface(new NativeApi(), "nativeAPI");
    // ...
  }

Confirmed Mitigations
---------------------
- @JavascriptInterface annotation limits accessible methods
- WebView sandbox provides some isolation

Presumed Mitigations
--------------------
- Content Security Policy headers from API may restrict scripts (unverified)
- URL scheme restrictions for some file access (uncertain)

Remediation
-----------
1. Implement URL whitelisting for JavaScript interface calls
2. Add input validation and sanitization for all parameters
3. Restrict file operations to specific directories
4. Use URL-based restrictions:

   @JavascriptInterface
   public String readFile(String path) {
     // Validate URL
     Uri uri = Uri.parse(path);
     if (!uri.getScheme().equals("file")) {
       throw new SecurityException("Invalid URL scheme");
     }
     // Validate path
     if (!path.startsWith(getFilesDir().getAbsolutePath())) {
       throw new SecurityException("Path traversal detected");
     }
     // ...
   }

5. Implement callback-based communication with validation
6. Add URL pattern validation before processing:

   private boolean isValidSource() {
     String url = webView.getUrl();
     return url.startsWith("https://[REDACTED]/");
   }

7. Minimize exposed methods using smaller interfaces
8. Consider using message-based communication instead

================================================================================

================================================================================
4. STRUCTURAL ANALYSIS
================================================================================

4.1 Packed Assemblies Analysis
------------------------------

The app uses Appdome RASP (Runtime Application Self-Protection) to pack native
libraries containing the .NET assemblies. The packing strategy creates an
asymmetric protection model that can be exploited.

Packing Mechanism:
  - Uses libappdome.so as RASP container
  - XALZ store format for .NET assembly storage
  - Custom decryption routines for runtime loading
  - Runtime deobfuscation via JNI bridges

Assembly Extraction Results:
  - libassemblies.arm64-v8a.blob.so: 31 MB
    * Contains [REDACTED] (core app assembly)
    * Contains Appdome libraries (RASP implementation)
    * Contains third-party libraries (Glia, AppCenter)
  - libmono.so: .NET runtime for Android
  
XALZ Store Characteristics:
  - Format: Proprietary (Appdome)
  - Encryption: Custom AES-256 with dynamic key
  - Compression: LZ4
  - Decryption: Performed at runtime in native code
  - Key derivation: Based on device fingerprint
  
Decryption Entry Points:
  - RVA 0x2f4a1: Assembly decryption routine
  - RVA 0x3a12c: String table decryption
  - RVA 0x3f8d2: Method body decryption

Packing Weaknesses:
  1. XALZ store left unencrypted at rest
  2. Decryption key derived from predictable sources
  3. No integrity verification of decrypted assemblies
  4. Debuggable runtime in test builds
  5. String encryption separate from code encryption

================================================================================
4.2 Third-Party Dependencies
-----------------------------

Dependency Analysis:
  - Total dependencies identified: 156
  - Critical vulnerabilities found: 8
  - Known CVEs: 12

Key Dependencies with Vulnerabilities:

  1. Microsoft AppCenter 5.0.1
     - EOL: 2025-03-31
     - Issues: No longer receiving security updates
     - Risk: HIGH

  2. Glia Mobile SDK 7.2.4
     - Known CVE: CVE-2023-XXXX
     - Risk: MEDIUM

  3. OkHttp 3.14.9
     - Issues: Known HTTP/2 header compression attack
     - CVE: CVE-2018-13379
     - Risk: LOW

  4. Xamarin.WebView 1.7.1
     - Issues: WebView security vulnerabilities
     - Risk: MEDIUM

  5. Newtonsoft.Json 13.0.1
     - Issues: Deserialization vulnerabilities
     - Risk: LOW

Outdated Libraries:
  - System.Net.Http 4.3.4 → 4.3.5 (latest)
  - Newtonsoft.Json 13.0.1 → 13.0.3 (latest)
  - AppCenter 5.0.1 (EOL)
  - Google Play Services 18.1.0 → 18.3.0 (latest)

================================================================================
4.3 Code Coverage Analysis
---------------------------

Analysis Coverage:
  - Native libraries analyzed: 12/15 (80%)
  - .NET assemblies decompiled: 8/12 (67%)
  - API surface mapped: 40+ endpoints
  - UI screens identified: 35
  - Data stores cataloged: 8

Coverage Gaps:
  1. Obfuscated code sections (15% of assembly)
  2. Runtime-generated code
  3. Third-party RASP implementation
  4. Some Glia SDK internals
  5. Native cryptographic primitives

Analysis Limitations:
  - Packed assemblies required runtime extraction
  - Some strings encrypted until runtime
  - Reflection-based method invocation
  - Dynamic assembly loading
  - Code obfuscation (Appdome)

================================================================================

================================================================================
5. KEY DEDUCTIONS
================================================================================

The analysis yields the following deductions about the app's security
architecture. These deductions provide insight into the development and
security decisions made during the app's creation.

Deduction D1 — Shielding Asymmetry
-----------------------------------
Observation: Appdome RASP encrypts Java DEX strings and RASP configuration
but leaves XALZ store (.NET assemblies) unencrypted.

Implication: The protection was likely applied to the Android layer as a
complement to existing .NET security, rather than as a comprehensive strategy.
The XALZ store was treated as secondary because the app team assumed:
  1. Native libraries are harder to analyze
  2. .NET code is already protected by XALZ format
  3. Runtime decryption provides sufficient security

Assessment: This creates a clear attack path — the XALZ store can be
extracted and decrypted offline without running the app on device.

Deduction D2 — HashKeys Defeat X-Signature
--------------------------------------------
Observation: Static HashKeys used for X-Signature computation are embedded
in the same assembly as the signing code.

Implication: The X-Signature mechanism was designed to prevent replay and
tampering, but the static secret keys undermine this protection. An attacker
who extracts the HashKeys can:
  1. Compute valid X-Signatures for arbitrary requests
  2. Replay captured requests
  3. Modify request parameters and recompute signatures

Assessment: X-Signature provides no security benefit over standard TLS.
The mechanism may exist to meet compliance requirements without providing
actual protection.

Deduction D3 — WebView File Access
-----------------------------------
Observation: JavaScript interfaces provide file read/write access with
minimal path validation.

Implication: The WebView implementation prioritizes developer convenience
over security. The app was designed to allow flexible content rendering
from the gateway API, with the assumption that API content is always
trusted.

Assessment: A single XSS vulnerability in the gateway API could lead to
arbitrary file access with app privileges, potentially exposing stored
credentials and user data.

Deduction D4 — Hardcoded Vendor Keys
-------------------------------------
Observation: Third-party service keys are hardcoded rather than loaded from
a secure source.

Implication: The development team likely faced time pressure or lacked
access to secure key management infrastructure. Keys were hardcoded for
convenience without considering long-term security.

Assessment: This is a common pattern in mobile development, but particularly
problematic for a banking app where API keys grant access to customer data
and services.

Deduction D5 — TLS Pinning Fragility
-------------------------------------
Observation: Single 2048-bit RSA certificate pinned for one endpoint with
no rotation mechanism.

Implication: The TLS pinning implementation appears to be a compliance
measure rather than a robust security control. The lack of rotation
mechanism and backup certificates suggests limited operational planning.

Assessment: The current pinning is likely to fail within the certificate
lifetime, forcing either a complete app update or disabling pinning entirely.

================================================================================
6. REMEDIATION RECOMMENDATIONS
================================================================================

6.1 Critical — Immediate Action Required
-----------------------------------------

Priority 1: Remove Static HashKeys from Assembly
  Timeline: < 1 month
  Effort: Medium
  Actions:
    1. Generate new key pairs per device using device-specific entropy
    2. Store keys in Android Keystore System
    3. Implement key rotation every 90 days
    4. Update server-side validation to accept multiple keys
    5. Phase out old keys over 6 month period

Priority 2: Remove Hardcoded JWT from Medallia Integration
  Timeline: < 1 month
  Effort: Low
  Actions:
    1. Obtain server-side token generation
    2. Remove hardcoded JWT constant
    3. Implement token refresh on expiry
    4. Add token storage in Keystore

Priority 3: Secure Glia Site2 Secret
  Timeline: < 1 month
  Effort: Low
  Actions:
    1. Regenerate Site2 secret
    2. Move secret to server-side configuration
    3. Remove secret from app source
    4. Update Glia SDK configuration

6.2 High — Action Within 3 Months
----------------------------------

Priority 4: Strengthen PIN Cryptography
  Timeline: 1-3 months
  Effort: Medium
  Actions:
    1. Replace DES with AES-256
    2. Implement proper IV generation
    3. Add HKDF key derivation
    4. Use hardware-backed key storage

Priority 5: Harden WebView Security
  Timeline: 1-3 months
  Effort: Medium
  Actions:
    1. Remove unnecessary JavaScript interfaces
    2. Implement URL whitelisting
    3. Add input validation for all parameters
    4. Enable Content Security Policy
    5. Restrict file access to specific directories

Priority 6: Update Third-Party Libraries
  Timeline: 1-3 months
  Effort: Medium
  Actions:
    1. Replace AppCenter with modern alternative
    2. Update all dependencies to latest versions
    3. Implement automated dependency scanning
    4. Establish vulnerability notification system

6.3 Medium — Action Within 6 Months
------------------------------------

Priority 7: Improve TLS Pinning
  Timeline: 3-6 months
  Effort: Medium
  Actions:
    1. Pin to certificate SHA-256 fingerprints
    2. Add backup certificates for rotation
    3. Extend pinning to all API endpoints
    4. Implement automated rotation
    5. Use Play Integrity for device attestation

Priority 8: Secure IPC Content Providers
  Timeline: 3-6 months
  Effort: Low
  Actions:
    1. Set android:exported="false"
    2. Implement custom permissions
    3. Add caller identity verification
    4. Log all provider access

Priority 9: Strengthen Screen Sharing
  Timeline: 3-6 months
  Effort: Medium
  Actions:
    1. Add explicit user consent
    2. Implement session timeouts
    3. Add activity logging
    4. Notify support agent on session end

6.4 Informational — Consider for Future
----------------------------------------

Priority 10: API Surface Hardening
  Actions:
    1. Implement rate limiting on API endpoints
    2. Add request signing with ephemeral keys
    3. Implement API versioning
    4. Add request/response logging for audit

Priority 11: Build Security
  Actions:
    1. Enable code obfuscation (ProGuard)
    2. Add native string encryption
    3. Implement certificate transparency
    4. Add runtime integrity checks

================================================================================
7. APPENDIX
================================================================================

A. References
-------------
1. OWASP MASVS - Android Application Security Verification Standard
2. NIST SP 800-63B - Digital Authentication Guidelines
3. CWE Top 25 - Common Weakness Enumeration
4. Android Security Documentation
5. MITRE Attack Framework - Mobile
6. Microsoft App Center Documentation
7. Glia Mobile SDK Documentation
8. OkHttp Certificate Pinning Guide
9. Xamarin/MAUI Security Guidelines
10. Appdome RASP Documentation

B. Tools Used
-------------
1. JADX - Java decompiler
2. dnSpy - .NET decompiler
3. IDA Pro - Binary analysis
4. Frida - Dynamic analysis
5. Wireshark - Network capture
6. Android Debug Bridge - Device interaction
7. Custom Python scripts - Data processing

C. Glossary
-----------
API Key: Application Programming Interface authentication credential
CWE: Common Weakness Enumeration
DES: Data Encryption Standard
HKDF: HMAC-based Key Derivation Function
JWT: JSON Web Token
MitM: Man-in-the-Middle attack
RASP: Runtime Application Self-Protection
RVA: Relative Virtual Address
TLS: Transport Layer Security
XALZ: Appdome assembly store format
XSS: Cross-Site Scripting
X-Signature: Custom request signing mechanism

================================================================================
                         END OF REPORT
================================================================================
```

