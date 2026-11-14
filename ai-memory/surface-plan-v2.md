# SURFACE ANALYZER OVERHAUL — PLAN v2 (canonical; supersedes surface.txt S-list)
Written 2026-11-14. Inputs: surface.txt (0.2.0 line verdicts), plan.txt
(S/A/B/C/D ladder + doctrine), appdev.txt v2 (Android knowledge, consumer
contract §15, tripwires §16, ritual §17), Pipeline/AI-handoff decisions
(plan.txt §8), user directive this session: periodic output dumps, structure
everything for the final AI tool call, never-static terminal.
MEMO TO SELF: read appdev.txt §0-§1, §13, §15, §16 before every work item.

================================================================================
1. PURPOSE RESTATED (what this tool IS after the overhaul)
================================================================================
The surface analyzer is the brain of the pipeline: it consumes the decoded
app + original APK and produces the machine-shaped KNOWLEDGE BASE of the app:
every fact, every hint, every deduced behavior, every coverage gap — mapped,
deduplicated, evidence-cited, confidence-labeled. Its data plane is read by
(a) the dossier/briefing generator (Phase D), (b) the final AI tool call
(handoff consumer), (c) reconcile/final report compatibility layer (Phase C).
Its terminal plane proves liveness continuously. Terminal silence = bug.
"The tool that catches everything from the smallest hint to the biggest
vulnerability, maps it all, and hands it to the reasoner — fast to consume,
impossible to confuse."

================================================================================
2. DESIGN PILLARS (binding on every item)
================================================================================
P1 EXHAUSTIVE: no budget, no cap, no unsearched area; every planned content
   class in appdev.txt §4 gets a parser (or a documented gap in the cover
   ledger).
P2 DEDUPED-BY-FINGERPRINT: value-level identity everywhere (URLs, domains,
   strings, keys, routes, class refs). Multi-occurrence = one fact +
   occurrence count + representative evidence (≤3) + full evidence on disk.
P3 DEDUCE-NEVER-GUESS: deduction templates fire only on conjunctive facts;
   every deduction cites input fingerprints + file:line chains; similarity
   is a labeled hint; packed/obfuscated apps DOWNGRADE confidence globally.
P4 STREAMING + CHECKPOINTED: work is written to disk incrementally; a crash
   resumes from the last checkpoint (per-stage, per-file-batch); output
   files are always parseable (never truncated/mid-write; atomic replaces).
P5 ALWAYS-ALIVE TERMINAL: never blank/frozen; single-line \r updates,
   ≤2s max silence, sub-unit progress on long units; one or a few lines,
   no constant scrolling print.
P6 TOKEN-EFFICIENT SHAPE: dense, deterministic, deduped facts w/ exact
   pointers (pull context, don't push); coverage ledger verbatim; graded
   briefing (facts → verified → hints → unchecked). Lives in data plane so
   the briefing generator stays thin.
P7 COMPAT GUARDS: existing consumer keys (final_run.py, reconcile_run,
   tests) keep working until Phase C migrates layout; changes documented in
   appdev.txt §15 per commit.
P8 SEQUENTIAL/LOW-HW: one file at a time; cheap per-file memory; no
   parallelism inside the analyzer; heartbeats carry enough state to resume.
P9 MODEL-AGNOSTRIC AI HANDOFF: ALL output except trufflehog VERIFIED
   findings is authored for the final AI tool call and must remain usable
   by virtually any capable model. Concretely: self-describing schemas
   (every file explains its own fields), plain JSON/JSONL/Markdown only,
   no project-internal jargon without an inline definition in BRIEFING.md,
   no叙事/IDs referencing knowledge outside the folder, evidence chains
   machine-verifiable from the folder alone, stable invariants (same key
   means the same thing in every artifact/run), paging-friendly size bands
   (the briefing indexes everything; no single file is load-bearing), and
   no reliance on model-side memory, tools, or prior context.
P10 ACTIVE-AGENT HANDOFF (user directive 2026-11-14): the handoff does NOT
   treat the AI as a read-only reporting tool. Every artifact's output must
   include the direction, locations, and working space for the AI to
   ACTIVELY EXTEND the analysis: a per-artifact investigation playbook
   (open leads ranked, with the exact evidence locations to continue from
   and suggested methods), a workspace permission map (what is immutable
   evidence vs where the AI may write), and a defined finish-line state. An
   AI with tool access should be able to work the folder directly (decode,
   grep, verify, extend facts); an AI without tool access must still be
   able to do the deepest possible written analysis from the same files.
   Model-agnostic phrasing law still applies: playbooks state GOALS with
   suggested methods, never hard commands.

================================================================================
3. ARCHITECTURE (target module layout)
================================================================================
analysis/surface/  (new package; apk_surface.py becomes a facade for
        analyze_apk_surface() + run_static_surface_analysis() so unaffected
        consumers (CLI run stage, integration tests) keep their call shape)
  __init__.py            : public facade only.
  progress.py            : shared ProgressPrinter (P5): state machine,
                           \r-rendered status line, 2s flush floor, counters,
                           sub-progress stack. One instance per artifact +
                           reused by future stages (shared helper — S5 done
                           once here for surface; trufflehog/runner adopt it
                           in their own phases, no coupling in S).
  classify.py            : S-a. single-walk decode-tree classifier routing by
                           (filepath, magic, suffix) → parse/scan target;
                           text sniff (4KB printable ratio + NUL) for
                           unknown suffix; never two passes over the tree.
  manifest_v2.py         : S-b. full element/attr map (facts) + derived
                           findings (deep links, meta-data keys, providers,
                           backup posture, NSC incl domain-config + anchors).
  sweep.py               : S-c. line-regex backbone: compiled alternation,
                           URL/domain/IP/route/header extraction with
                           scheme classification, normalization, private/IDN
                           tags, base64 candidate decode, context snippets
                           with size caps; per-suffix structured passes
                           (xml/json/properties) feeding the same fact pool.
  facts.py               : Fact store: fingerprint dedup, occurrence count,
                           representative evidence, fingerprint → full
                           evidence sqlite-lite (jsonl on disk per artifact:
                           facts.jsonl = one fact per line, streaming).
  deductions.py          : template engine (appdev.txt §12 catalog): facts in
                           (fingerprints), deductions out (narrative,
                           confidence, cited chains). Template registry is
                           a plain list in code, versioned with analyzer.
  coverage.py            : per-file coverage ledger (parsed/scanned/binary/
                           failed/packed-limited/downgrades) → unknowns.
  checkpoint.py          : S-d. atomic checkpoint writer: per artifact write
                           partial sections (manifest.json, progress state,
                           facts.jsonl append, sweep_state) so a resume
                           never repeats completed work; final assembly
                           replaces checkpoint with static-analysis.json.
  serialize.py           : S-e. the COMPAT reshape: output keeps consumer
                           keys (compat guard §15) and adds the new model
                           (facts/deductions/coverage/handoff sections).
  driver.py              : move of run_static_surface_analysis (+ run
                           marker refresh per artifact (S-f), skip-reuse
                           keyed on analyzer version, retain integrity
                           recheck of source APK before DEX pass).
ardo (unchanged): androguard_dex.py — stays as-is architecturally (its facts
        merge into the same fact pool; its input-hash guard stays).
Deferred to Phase C (NOT this overhaul): run-folder layout migration,
registry/executor wiring, evidence.py integration, dossier generator.

================================================================================
4. EXECUTION ORDER (replaces surface.txt S-a..S-g; each item = commit + tests)
================================================================================
S1. PROGRESS + CHECKPOINT SCAFFOLD (progress.py, checkpoint.py) with contract
    tests (silence >2s = fail; crash-replay resume test). Lands first so all
    later items are born observable + resumable. ALSO fixes S3 (imports),
    removes the 10s heartbeat (currently L429) to ≤2s, adds hash-loop
    sub-progress in driver, marker refresh per artifact.
S2. CLASSIFIER + SINGLE WALK (classify.py): one os.walk, route decisions,
    no repeated reads, symlink-skip accounting preserved, extension counter
    from same pass. Includes the BIG data-plane win: original-APK zip
    inventory (every member: path/size/sha256 method) + nested-archive
    detection (zip/jar/apk/dex/elf magic) as facts. (merges old S-a + S-d
    core since both are the "walk/report what exists" stage).
S3. MANIFEST V2 (manifest_v2.py): full map + facts + derived findings per
    surface.txt 1A list (deep-link tuples, meta-data keys+values, provider
    authorities, queries, backup config incl dataExtractionRules +
    fullBackupContent resolution, NSC domain-config/anchors, allowBackup
    default-true deductions, anomaly checks: versionCode/min>target).
    Compat: manifest facts keep current keys (§15).
S4. SWEEP V2 (sweep.py): schemes classification (generic scheme match),
    URL canonicalization + dedup via fingerprints; user:pass@, IPv6,
    host:port pairs; private/IDN/dev-host tags; base64/percent decode
    candidates; retrofit windowed state machine; API_HEADER context class;
    rate-limit proximity over ALL evidence; per-line lowered only where
    needed; context snippets (±2 lines, char-capped; S4 snippet cap);
    per-suffix structured passes for xml/json/properties to catch value-key
    pairs regex can't (strings.xml google-services-style keys, .env).
S5. FACTS + DEDUCTIONS (facts.py, deductions.py): wiring all upstream
    parsers into the fingerprint store; first deduction templates (SDK
    histogram via package-root classifier; packed/obfuscation downgrade;
    mismatch "permission requested, no usage found"; API surface
    reconstruction from retrofit data). Deduction registry versioned.
    NOTE: because the WORK ASSIGNMENT is the program's core product
    (plan.txt PROGRAM IDENTITY), S5's output templates are composed as
    handoff directions: each deduction carries its next-step suggestion
    for the terminal AI (e.g. "decode, correlate with sibling, confirm
    callback"), so §7A workbook content emerges naturally here.
S6. SERIALIZATION + COMPAT RE-SHAPE (serialize.py): assemble final
    static-analysis.json with: compat inventory/findings preserved, plus
    facts.jsonl, deductions, coverage ledger, metrics{raw,distinct},
    limitations refreshed; analyzer version 0.3.0; reuse-gate changed to
    0.3.0-only w/ stale=obsolete; findings dedup changes counts
    (finding_count distinct) — final_report's consumer display unaffected
    (feeds from same lists).
S7. DRIVER SWITCHOVER (driver.py) + full test campaign S-g surface.txt
    (manifest v2 fixtures, endpoint variants, private/IDN, base64, nested
    archives, sniffing, dedup contract, emit-contract, crash-resume test).
S8. LIVE VALIDATION on the Antennapod fixture + one large real APK (observe
    wall-clock delta vs 0.2.0; record in decisions log §14 appdev.txt).
Then: reconcile plan.txt (post-S status) + plan Phase A ceilings (the
    remaining budget/cap deletions land in S code from the start — the
    sweep/classifier are built WITHOUT budgets by design; Phase A for the
    other modules stays as planned).

================================================================================
5. OUTPUT PLANE (what the artifact's data looks like — the AI's first byte)
================================================================================
Per-artifact stable directory (paths unchanged until Phase C):
results/<pkg>/<ver>/<digest>/
  static-analysis.json    : compat source of truth + summary layers:
      manifest_facts, inventory (compat keys preserved), findings (deduped,
      severity/confidence/verification_state each), fact_summary (by kind:
      count + top values), deductions (templates citing fingerprints),
      coverage (ledger + content-class completeness), metrics {raw,distinct},
      limitations, analyzer {id,version}, artifact identity (pkg,ver,
      sha256, source paths + hashes).
  facts.jsonl             : the streamed fact log (append during run, atomic
      final replace; one JSON object per line per fact w/ full evidence).
  sweep_checkpoint.json   : transient; removed on success.
  checkpoint_state.json   : resumable state machine point (stage, file
      cursor, counts); removed on success.
Plus (unchanged): dex_analysis embedded in static-analysis.json as today.
Plus (Phase D): BRIEFING.md + dossier land HERE + handoff folder (plan §8),
which is why the serializer MUST emit the graded, pointerized sections now.
Terminal (P5) SHAPE: "Surface pkg vN: 61% (1453/2390 files) smali 72%
endpoints 1.2k findings 5.3k (distinct 2.1k) 43s" — one \r line refresh.

================================================================================
6. PERFORMANCE BUDGET (docile low hardware; no ceilings though)
================================================================================
- One fs traversal; one file read per file; line streaming for text (no
  whole-file text() beyond sniff small cap; sweep reads line by line from
  binary chunks; keep per-line lowered only where needed).
- Compiled alternation for CODE_RULES + per-suffix subsets; URL/domain/IP
  single alternation with named groups → classify after.
- Fact store in memory bounded by distinct values (dedup law) NOT by
  occurrences; evidence appended to disk (facts.jsonl) with representative
  list in memory.
- O(1) dict lookups replace the linear containment checks (S2 old).
- Everything sorted at serialization; deterministic on every machine.
- Expected outcome: strictly faster than 0.2.0 on big APKs despite more
  extraction; measured in S8 and recorded.

================================================================================
7. TEST MATRIX (S-g contract; fixtures under tests/fixtures/surface/)
- manifest v2: deep links (scheme/host/path), meta-data keys, provider
  authorities + grantUri, queries, backup rules resolution, NSC
  domain-config/anchors, allowBackup default-true deduction, anomaly keys.
- sweep: scheme classification (content://, intent://, custom), URL
  canonicalization dedup, user:pass@, IPv6/pairs, private/IDN tags, base64
  decode hits, ACROSS-file counts merge, rate-limit proximity all-evidence.
- facts: fingerprint merge counts; representative ≤3; jsonl resumable.
- deductions: template firing on fixture conjunctions; citation law (no
  deduction without fingerprints); packed downgrade test.
- checkpoint: mid-sweep crash → resume completes without duplicates.
- progress: 2s contract with fake clocks; \r line shape.
- compat: final_report consumer keys unchanged (fixture assert); reconcile
  statuses unchanged; integration test green (test_pipeline_integration).
- adversarial: unicode/NUL/BOM, 0-byte files, huge single line, deep dirs,
  symlinked entries (skip + count), non-UTF8 bytes, clashing names.

================================================================================
7B. PROMPT TEMPLATE + NUMBERED WORKCHAIN (decided 2026-11-14; CORE PRODUCT)
================================================================================
The AI work assignment becomes an EXPLICIT PROMPT PROGRAM shipped with the
repo: a prompt template + numbered instruction chain given to the terminal
AI alongside the artifact folder. THIS REPLACES "hand over folder, let the
AI figure it out" (rejected: nondeterministic, attention-lossy, anchored).
Why it wins: deterministic (any model, same sequence); inspectable by the
operator before use; token-frugal (load only what a stage needs); progress
is native; the anti-anchoring raw-map-first order is enforced, not hoped.

STRUCTURE (that goes into the working .apk folder; Phase C natively, and
the interim Phase S folder growth adapts paths):
  <artifact folder>/ai_handoff/
    00_PROMPT_TEMPLATE.txt : static master prompt: role, doctrine, rules
        of engagement, output conventions, schema vocabulary glossary,
        confidence labels, working-memory protocol (NOTES.md), finish-line
        definition. Ends with: "Now read 1.txt to start the workload."
    01_map_raw.txt ... NNN : numbered stages. EACH file (static skeleton +
        per-artifact GENERATED content interpolated by the serializer):
        a) mechanical steps; b) reasoning standard + definition-of-done
        (checkable; no stage closes without satisfying it); c) exact
        evidence locations (location ledger slice) + suggested methods
        (goals, not commands); d) what may/may not be written (permission
        map slice); e) pointer "Now read <next>.txt".
  Expected stage skeleton (names stable, count variable):
    01 map raw tree (FULL read of decompiled apk; own observations into
        NOTES.md FIRST, before any tool output is opened)
    02 program output map (facts/findings/coverage read-through)
    03 trace hints i..n (per-lead work files, generated from playbook)
    04 deductions + correlations (anchors to endpoints, signers, versions)
    05 dossier assembly (templates defined in 00; ai_analysis.json + claim
        citations)
    06 closure + free exploration license + final review (definition of
        finished work; allow the AI to add anything found while exploring)
  - WORKING MEMORY BANK (decided 2026-11-14): 01_map_raw instructs the AI
    to create ai_analysis/memory/ (its OWN organized subfolder) and use it
    as its active memory throughout: per-lead notes, grep/hash/decode
    dumps, working hypotheses, cross-reference tables; save as much data
    as possible for itself (disk is free; only reads cost tokens). Memory
    survives compaction/session-splicing -> the analyst re-enters without
    redoing raw mapping. Scratch is INTERNAL to that subfolder; top-level
    ai_analysis/ keeps only deliverables (ai_analysis.json, final dossier,
    decision log) so scratch can never be mistaken for output.
  - STAGE 06 (final, from the template): "SET YOUR AGENTS FREE" = CLOSURE
    STAGE: adversarial self-audit ("assume you missed something; hunt for
    it") + free exploration + verification/fix of gaps; capability-adaptive
    (spawn agents if the environment allows, else iterate solo). Converges
    with a STOP CONDITION: leads triaged, coverage lines expanded-or-
    explained, closure report written (verified / fixed / open-with-reasons)
    BEFORE the session ends (linear-and-finishable doctrine).
DESIGN LAWS for the chain:
  - Every stage has a definition-of-done expandable, and the doctrine is
    inline (deduce from data, never guess; evidence=folder citations).
  - Static/shared portions live in the template; per-artifact data (leads,
    ledgers, inventories) are interpolated by the S6 serializer + Phase D.
  - Working memory: ai_analysis/NOTES.md accumulates; later stages may
    consult earlier notes instead of re-reading big files.
  - Capability-adaptive: goals not commands; a no-shell model does written
    analysis, a shell model acts on the folder.
  - Lockable/composable: the template is one artifact users can edit;
    numbering stable across versions (00..N); formatting plain text.
Relationship to the pipeline: surface-plan S6 writes the generated content;
Phase D composes dossier and 00 template renders the master prompt.

================================================================================
7A. ACTIVE-AGENT HANDOFF LAYER (P10 implementation, lands with S6/S7)
================================================================================
Every artifact's static-analysis.json gains a WORKBOOK section, and the
per-run/per-artifact BRIEFING.md (Phase D) renders from it. Content:
1. MISSION + RULES: what this folder is, the doctrine (deduce from data,
   never guess), confidence labels (tool_verified / deduced / hint /
   ai_deduced), and the finish line (below).
2. LOCATION LEDGER: every finding/entry/fact listed with its exact
   file:line evidence locations relative to the folder, plus what each
   fact KIND means and how to re-verify it by hand (hash recompute,
   reopen file, re-run decode).
3. PERMISSION MAP: immutable (ledger/manifests/history/bundle bytes -
   read only) vs WORKING AREA (writable): a designated ai_analysis/
   directory in each artifact folder where the AI writes its overlay:
   ai_analysis.json (findings with verification_state=ai_deduced, cited
   folder-relative evidence) plus its narrative dossier. Corpus files
   untouched; the overlay is additive and diffable.
4. INVESTIGATION PLAYBOOK per artifact (the direction):
   - OPEN LEADS: ranked list of what static analysis could NOT close -
     packed/encrypted blobs (with decode suggestions keyed by observed
     magic bytes), unproven endpoint semantics, remote-config-driven
     behavior, native .so strings to mine, deltas vs sibling versions in
     the same workspace (stated conditionally when present).
   - SUGGESTED METHODS phrased as goals, never hard commands (P9/P10
     law), e.g. "decode this base64 candidate and reconcile the decoded
     value against the endpoint inventory; record the outcome in the
     overlay with citations".
   - DEAD END markers (attempts already made -> do not repeat).
5. FINISH LINE per artifact: every coverage-ledger entry either expanded
   by the AI's own work or expressly closed with a reason; every open
   lead triaged (pursued/dismissed with reason); overlay + final AI narrative
   written into the working area; every AI claim cites folder-relative
   evidence. Run-level briefing (Phase D) aggregates per-artifact finish
   states into an overall run closure ("sew up the process neatly").
6. Capability-adaptive: an AI with shell/tool access works the folder
   directly (decode, hash, grep, extend facts); an AI without still
   produces the deepest possible written analysis from the same files.
Default landing zone for the AI overlay:
  runs/<run_id>/<pkg>/<ver>/<digest>/ai_analysis/   (post-Phase-C layout)
  (interim Phase S: results/<pkg>/<ver>/<digest>/ai_analysis/)

================================================================================
8. RISKS + GUARDS
================================================================================
R1 breaking final_report: guard S6 with compat fixture assert (§15 VERIFY
   against current source BEFORE S6 edit).
R2 checkpoint/resume bugs duplicating facts: fingerprint store is the idem-
   potence insurance (double-appended same fingerprint merges); plus
   surviving checkpoint replay test.
R3 \r progress vs CI logs: ProgressPrinter falls back to newline every
   ~5-Heartbeat if not a TTY (detect isatty), no control-char in logs.
R4 huge findings: entire JSON body big — facts.jsonl stays the streamed
   file; static-analysis.json can grow but remains server-loadable; fine
   for per-artifact folder size (hardlinks cheaper later).
R5 scope: Phase C items (run-folder layout, registry, evidence store,
   dossier) DO NOT happen inside S; note-only per tripwire §16.6.
================================================================================
END SURFACE-PLAN-V2 — surface-overhaul plan canonical.
Surface.txt order retained for reference; this file supersedes it for work.
================================================================================
