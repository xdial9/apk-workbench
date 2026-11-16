# AI-MEMORY — INDEX & STATE (read first, update often)
Owner: the agent. Purpose: active memory bank / map. Frequent reads and
writes required: no session starts without reading STATE; no state change
ends without updating STATE.

## FILE MAP (what lives here and what it's for)
- INDEX.md (this file)  : always-current state + protocol + file map.
- surface-plan-v2.md    : CANONICAL surface-analyzer overhaul plan (v2;
                          supersedes surface.txt's S-order; adds checkpoint
                          dumping + progress + AI-handoff shaping).
- native-plan.md        : CANONICAL native (JNI) plan N1..N13 — discovery +
                          mapping to 100% (measurable identities I1..I5).
                          Owns the native track; appdev.txt §4 stays the
                          domain knowledge, this file owns steps/state.
- appdev.txt            : Android domain knowledge + consumer contract +
                          drift tripwires + operational ritual (v2). Read at
                          every session start; §1 STATE MIRRORS this file.
- plan.txt              : master plan (doctrine, phase ladder W/S/A/B/D/E,
                          tool command specs, run-workspace design).
- surface.txt           : surface-analyzer line-by-line verdicts (0.2.0) +
                          execution order S-a..S-g.
- firstreport.txt       : full-codebase audit baseline (2026-11-13) +
                          overall opinion — stable reference, rarely changes.
- acquisition-review.md : acquisition rework audit trail (F1..F7).
- todo.md               : ACTIVE resume file. Phase order, Unit 1 spec,
                          environment constraints, tripwires. Read after this.
- resumeprompt.txt      : user-authored; do not edit.
NOTE: repo /prompts/0.txt..6.txt still assume the OLD folder shape in places
(old `ai_handoff/` naming in surface-plan-v2 §7B is superseded; prompts are
0.txt..6.txt at the workspace root). Prompt text edits are part of Phase W /
the dry run, NOT done yet.

## RULES OF THIS FOLDER (agent-maintained)
1. STATE MUST BE TRUE AT ALL TIMES. If it isn't, fix it before working.
2. Knowledge validated by fixtures graduates from transient notes into the
   right file; invalid or superseded entries get updated/corrected — a wrong
   entry is worse than a missing one (deduce-not-guess doctrine).
3. Duplicate-maintenance discipline: canonical home per topic
   (doctrine -> plan.txt; surface detail -> surface.txt; Android knowledge +
   contracts -> appdev.txt; session state -> here). Other files may reference
   but not fork content, except transient scratch.
4. Append-only where history matters (decisions logs), mutable everywhere
   else (correctness beats immutability for memory).
5. Mark uncertain entries VERIFY — never bake untagged guesses in.

## SESSION PROTOCOL
START: read INDEX.md -> appdev.txt §0/§1/§15/§16/§17 -> relevant phase file.
DURING: register risks/hallucination doubts as VERIFY notes immediately.
END: update STATE (phase item moved? decisions? VERIFYs resolved?) + tick
surface.txt/plan.txt checkboxes if applicable.

## STATE (as of 2026-11-16, updated by agent)
- VERIFIED SNAPSHOT 2026-11-16 (git + pytest, not memory): working branch
  feat/native-elf-reader; tests 271 green; native N1-N13 all committed
  (N13 asset/container-embedded .so = f1b921d). Before this snapshot those
  commits were local-only; they are now pushed and main/origin/main are
  fast-forwarded to them. feature/goopdl-account-auth and feat/handoff-folder
  are stale copies of the old main (9d4fea4). NEXT UNIT is still per-bundle
  workspace + freeze (todo.md Unit 1): no code for it exists yet. Lines below
  that say "N13 deferred", "262 tests" or "Branch: feature/goopdl-account-auth"
  are history, superseded by this bullet.
- Branch: feature/goopdl-account-auth (S8 perf 062973b; handoff writers
  committed 2026-11-14 as 6e8dcaf; live account-mode validated; tests 211
  green). 2026-11-16: citation-root parameterized (D-1 step 2) — see
  "CITATION-ROOT PARAMETERIZATION" below; tests 213 green.
- GIT ORGANIZATION 2026-11-16: working tree split into 4 topical commits
  (docs / cap-free analysis plane / secrets split / regression fixes) on
  feature/goopdl-account-auth, fast-forwarded into main (main was an
  ancestor: 0 commits on main not already on the branch), then main and
  the new working branch feat/handoff-folder were pushed. HEAD 9d4fea4.
  feature/goopdl-account-auth is now redundant (identical to main) but was
  left in place. Tests 217 green.
- SECRETS SPLIT 2026-11-16 (user decision): verified TruffleHog results go
  to a human .txt (trufflehog/findings-verified.txt), the complete set
  (verified + unverified JSON files) stays for the AI handoff. Report plane
  lists verified only, counts unverified (trufflehog_unverified_count /
  unverified_trufflehog_findings_retained), never aborts.
- NATIVE TRACK OPENED 2026-11-16: ai-memory/native-plan.md written after a
  line-by-line review of the native path (was strings-only:
  apk_surface.py:235-257, 432-465). Crown jewel 5 was measured at ~15%.
- NATIVE TRACK IMPLEMENTED 2026-11-16 on branch feat/native-elf-reader
  (branched from main @ 9d4fea4; main untouched). New modules
  analysis/surface/native_elf.py (stdlib ELF reader) and
  analysis/surface/native.py (JNI demangle+join, load sites, streamed
  strings incl. UTF-16LE, evidence-only findings). Native facts now cite
  path@0xOFFSET (handoff + workbook). Metrics carry I1/I2 identities;
  status goes partial for any unparseable .so. 262 tests green. N13
  (asset-embedded .so) still deferred; NEEDED-graph reasons done.
- Phase: Surface analyzer overhaul planning DONE (ai-memory/surface-plan-v2.md
  is canonical; supersedes surface.txt's S-order and folds in dump/checkpoint
  + terminal + AI-consumer shaping; P9 MODEL-AGNOSTRIC HANDOFF LAW + master
  plan D2 added on user request 2026-11-14: all non-trufflehog-verified
  output authored for any-capable-model consumption; P10/D3 ACTIVE-AGENT
  HANDOFF added (workbook/playbook/permission map/finish line — AI is a
  worker that extends analysis, not a read-only reporter).
  PROGRAM IDENTITY REFRAME (plan.txt top, 2026-11-14): the datamap +
  WORK ASSIGNMENT is the core product; terminal AI is the analyst whose
  mandated workflow is raw-map-first (anti-anchoring), then tool output,
  then trace-every-hint; all stages exist to serve the handoff.
  PROMPT WORKCHAIN DESIGN (surface-plan §7B, 2026-11-14): the work order
  ships as a prompt template + NUMBERED instruction chain inside the
  artifact folder (00_PROMPT_TEMPLATE.txt -> 1.txt -> 2.txt ...), each
  stage with reasoning standard, definition-of-done, location-ledger
  slice, permission map and read-next pointer. Replaces free-form handoff
  (rejected). The prompt template is a shipped program artifact; Phase S6
  writes the per-artifact generated files; Phase D composes the dossier.
  WORKING-MEMORY BANK + AGENTS-FREE CLOSURE (2026-11-14): the workchain
  directs the AI to build its own ai_analysis/memory/ subfolder (scratch,
  dumps, hypotheses; save liberally — disk is free, only reads cost) while
  deliverables stay on ai_analysis/ top level; stage 06 = adversarial
  closure/license ("set your agents free": verify/fix/cover gaps, with a
  stop condition + closure report so it converges, linear-finishable).
  WORKCHAIN DRAFT v1 LANDED (2026-11-14): repo /prompts/ contains
  0.txt..6.txt (master + 6 stages) + README_BUILD.md (construction split,
  interpolation slots, known gaps). Prompts note stage numbering 0..6
  (user chaining reads 0 then 1.txt). Next refinement after first live run.
- ACQUISITION REWORK (started 2026-11-14, at beginning per user order):
  commits 1b26eaa + 4f225e6 (pushed): F1 provenance (discover channels ->
  catalog -> bundle manifest), F3 rerun hygiene (.part purge + extra_files),
  F2 RESOLVED: one-time mid-download delivery refresh with frozen-plan
  digest guard (divergent delivery aborts with re-run guidance); prompts 0/2 + README updated; ai-memory/acquisition-review.md audit trail (F1..F7;
  F2 closed; F6/F7 documented; P2-2 pacing deferred to plan item A).
  Tests 156 passing. Remaining acquisition polish: minor.
- SURFACE OVERHAUL (plan v2): S1 9898217, S2 652a088, S3 7d1cb43, S4 9a55e64,
  S5 3794764, S6 5077a31, S7 e22faaf (all pushed; tests 205): S7 = adversarial
  campaign + REAL FIND: catastrophic ReDoS in DOMAIN_RE/HOST_PORT_RE (hostile
  huge label runs could wedge the sweep forever — violates never-frozen);
  fixed with possessive quantifiers on the unbounded groups; IPv6 second
  alternative extended (bounded). Consumer contract asserted on every result.
  S8 Antennapod DONE (a9ca7de: 1503s wall, partial due to androguard 64MB cap
  on a NORMAL app — Phase A proof; 4299/4164 findings; fact-evidence ledger
  bug found+fixed). S8 PERF (062973b): live profile -> compiled matchers,
  file-level dependency evidence, required-character gates; 300-file
  microbench 16.73s -> 6.02s (~2.7x); surface-only Antennapod 407s for
  15,290 files; parity verified (findings/inventory/manifest/deductions/
  fact core identical; only expected diffs were the 03:39 evidence fix and
  driver-only DEX/zip stages). Spotify 131MB acquired+verified (run
  c79180cf, 4 APKs), decoded 1.2GB. Pre-optimization run aborted at
  25,292/112,254 files / 2,351s (~10.8 files/s baseline only); optimized
  rerun launched 2026-11-14; see RESUME HERE.
  NEXT after S8: handoff contract. Writers for facts.jsonl + location_map.json
  are IMPLEMENTED AND COMMITTED 2026-11-14 (see "CANONICAL DESIGN DECISIONS"
  below for what is still missing and the agreed phase order). The next unit
  of work is the PER-BUNDLE WORKSPACE + FREEZE rework (item 1 of the
  post-review plan), then the prompt-chain dry run.
  Read "CANONICAL DESIGN DECISIONS" and "HANDOFF READINESS ASSESSMENT" below
  before choosing any work.
- Environment: repo /home/user/APK-Workbench; venv .venv/bin/python; pytest
  all-green baseline 205; apktool 3.0.3; trufflehog 3.99.8; androguard 4.1.4
  pinned; live fixture workspace /tmp/opencode/ws (VERIFY exists before use);
  optimized Spotify log /tmp/opencode/surface_spotify_optimized.log.
- Spotify heavy-case scan STOPPED BY USER 2026-11-14 04:52 at
  57,944/112,254 files (1,481s, ~39 files/s optimized, 6,227 endpoints,
  4,890 findings in memory). NOTHING PERSISTED: no static-analysis.json /
  facts.jsonl / location_map.json for any Spotify artifact, and the run
  marker is stale ("running", eligible 0) — do not treat it as a live run.
  Heavy-case validation remains INCOMPLETE; Antennapod is the only finished
  artifact. Rerun command preserved in todo.md; safe to rerun.
- Working files live in ai-memory/ (plan.txt, surface.txt, firstreport.txt,
  appdev.txt). Repo root still has a tracked plan.txt (legacy copy); treat
  ai-memory/plan.txt as canonical. surface.txt and firstreport.txt are gone
  from root (verified 2026-11-14). Do not delete the root plan.txt without
  the user's say-so.
- Branch decision: stay on feature/goopdl-account-auth until the user says
  otherwise (resolved; no longer an open question).

## CANONICAL DESIGN DECISIONS (2026-11-14 user review; binding)

PROGRAM PURPOSE (canonical restatement): this is a pipeline that prepares a
SELF-CONTAINED WORKSPACE FOR AN AI ANALYST. It acquires, decodes, maps and
packages one app bundle so that a capable model, given only that folder and
the master prompt inside it, can operate with direction and context, miss
nothing, run the full live validations, and return every verified result
plus evidence-backed theories it could not verify. TruffleHog is a
convenience that emits quickly-verified secrets; it is NOT the purpose of
the program and must not drive its design.

D-1 PER-BUNDLE WORKSPACE (user directive; replaces per-APK).
- Unit = one app VERSION BUNDLE: base.apk + all its splits (and asset packs
  when acquired). One folder per bundle, not one per APK.
- Path: results/<package_id>/<version_code>/<bundle_id>/
- bundle_id = the run manifest's index_sha256 (Play delivery-plan digest).
  VERIFIED 2026-11-14 on run c79180cf: all four Spotify rows carry the same
  index_sha256 = 6ae4f3aa267c77312806a652ef299833c0ac38bfd52d6c21121cd509a36c56c6.
  Use it; do not invent another digest.
- Decoded components get their own subtree: apktool/base/,
  apktool/split_config.arm64_v8a/, apktool/split_config.en/,
  apktool/split_config.xxhdpi/ (names from APK file stems).
- Original APKs stay in downloads/<package_id>-<version_code>/ and are NEVER
  moved (user requirement).
- CONSEQUENCE, must be fixed in the rework: surface/handoff.py hardcodes the
  citation root "apktool/". Under per-bundle trees the root is
  "apktool/<component>/", so that prefix must become a parameter and
  citations must read e.g. apktool/base/smali/com/x/A.smali:118. Both
  location_map.json and workbook.location_ledger are affected.
  STATUS 2026-11-16: DONE — parameter threaded end to end (see
  "CITATION-ROOT PARAMETERIZATION"). The driver already derives the value
  from the layout, so D-1 only needs the component subtrees to exist.
- OPEN (decide during implementation, do not assume): how the per-APK
  static-analysis.json files aggregate at bundle level. Proposal: keep
  surface/artifacts/<sha256>/static-analysis.json per APK + a bundle-level
  surface/bundle.json index. A single silently merged JSON is NOT approved.

D-2 IN-PLACE FREEZE, NO COPY.
- The bundle workspace IS the handoff folder. No copy of apktool/, no
  hardlinks, no symlinks.
- Rejected because: a hardlink shares the inode (chmod cross-talk; an
  in-place write corrupts evidence AND handoff at once), hardlinks cannot
  cross filesystems and cannot link directories; a symlink lets a write
  escape into the evidence tree.
- Integrity instead of duplication: at freeze time make evidence read-only
  (apktool/, surface/, trufflehog/, manifest/) and write hashes.sha256; add
  `apkwb verify-workspace <folder>` that recomputes and reports tampering.
  ai_analysis/ stays the only writable area (already stated by the workbook
  permission map).
- Marketing benefit: zero duplicate disk, and the folder zips into one
  portable handoff.

D-3 WORKSPACE LAYOUT (prompts 0..6 promise these names; make them true):
```
results/<pkg>/<version_code>/<bundle_id>/
  apktool/base/ ; apktool/<split>/     decoded components (frozen)
  surface/static-analysis.json         per-artifact aggregation per D-1
  surface/facts.jsonl                  one fact per line
  surface/location_map.json            index of every entry with file:line
  trufflehog/findings.json | status.json
  manifest/                            run-manifest row(s) + google-play-bundle.json
  0.txt .. 6.txt                       instruction chain, copied at freeze
  README.txt                           what this folder is, how to start
  handoff.json                         schema/tool/prompt versions + hashes
  ai_analysis/attempt-01/              ONLY writable area
```
- A stage that did not run writes status.json (status + reason); never leave
  a promised path missing.
- ai_analysis/attempt-01/ rather than bare ai_analysis/ so one folder can be
  handed to several models/attempts without resetting.

D-4 static-analysis.json RELOCATION COST (verified in source 2026-11-14).
- Moving it into surface/ breaks exactly two consumers:
  reporting/final_run.py:368 and database/workspace.py:327 (reconcile).
- Fix: read surface/static-analysis.json first, fall back to the legacy root
  path so existing artifacts still reconcile; add tests. No other consumer
  exists (grep confirmed).

D-5 TRUFFLEHOG SCOPE (user clarification; retracts the Phase B two-pass).
- Verified-only (--results=verified) is intentional and stays: it is the
  quick verified-secret output, nothing more.
- The AI does the rest; trufflehog is not the product.
- NO second scan. The old Phase B "HINT PASS" is RETRACTED (it re-traverses
  the tree and adds volume plus a parallel classification system).
- Sole future exception if a real gap appears: ONE unfiltered run split into
  verified findings + unverified hints (no extra traversal), so genuine but
  unverifiable material is not invisible. Not scheduled.

D-6 NO FULL REWRITE (user directive).
- Phase C "surface analyzer full rewrite" is CANCELLED as a rewrite; the
  "FINAL FULL REWRITE" line in plan.txt is corrected to a targeted,
  measurement-led refactor list.
- S1-S8 already removed the monolith, the quadratic character check, the
  hard caps and the adversarial failures that motivated the rewrite.

D-7 SIZE POLICY for batch acquisition (not on the critical path).
- Per-BUNDLE ceiling belongs in the DOWNLOADER, not discover: PlayApp has no
  size field, but PlayBundlePlan.files[].size is known before download.
- Must be an explicit, persisted policy: record package_id/size/policy/
  decision/reason. Today's "unavailable" skip is console-only — a real gap.
- --package always bypasses; an override disables the ceiling.
- Threshold comes from the measured size distribution (catalog +
  run_manifests), never a guessed round number.
- Pair with pipeline tiering (small -> full; large -> surface-first, DEX
  deferred) so large apps are not banned from the corpus.

D-8 WORKSPACE ON DISK, NOT TMPFS.
- Product default is already correct: ~/APK-Workbench/workspace
  (config.py:33), on the 633GB ext filesystem.
- The dev fixture override /tmp/opencode/ws is TMPFS: 1.9GB total, 337MB
  free. The 1.1GB Spotify tree lives in RAM (swap was 1.1GB used). Move the
  fixture to disk before any batch/bundle work; a copy of that tree inside
  /tmp cannot fit.

D-9 PROCESS (user directive 2026-11-14).
- ONE PHASE AT A TIME: complete one unit, stop, report; the user reviews
  before the next begins.
- Do not edit code while the user is asking a question. Answer first and ask
  before implementing (explicit correction after edits were made mid-Q&A).
- Do not push unless explicitly asked.

## HANDOFF READINESS ASSESSMENT (2026-11-14, agent opinion, evidence-based)

Context: user asked for a judgement of whether the overhaul is on track for
its stated purpose — run end to end, then hand off to ANY capable AI model
so it can operate at maximum efficiency, direction and accuracy.

VERDICT: the DESIGN is on track; the PROOF and the BUDGETING are not.
Architecturally this is the right shape and stronger than typical
"AI-ready" pipelines. Functionally it has never been executed once by a
real model, and its "everything is present" handoff does not scale in the
efficiency sense. Sequence should be: dry run -> volume hierarchy ->
machine-checked output contract -> Phase A ceilings.

What is genuinely right (keep; do not redesign):
1. It hands over WORK, not conclusions: workbook.playbook.open_leads +
   finish_line make the model an analyst with an assignment. A summary can
   be answered by summarizing; this cannot, which is correct.
2. Evidence discipline is real and enforced in the data: file:line cites,
   confidence labels (tool_verified/deduced/hint/open_question/ai_deduced),
   coverage ledger, limitations, diagnostics, acquisition hashes.
3. Raw-first law (map the tree before trusting tool output) is a genuine
   accuracy lever; it stops the model inheriting the analyzer's blind spots.
4. Nothing is hidden: coverage gaps become explicit leads. Unusual and
   correct for trust.

Where it is NOT yet on track (ranked by risk):
1. NEVER EXECUTED. prompts 0..6 have not been run by a model on a real
   artifact. Biggest risk in the whole overhaul, larger than any code item.
   Predictable first-run failures: unresolved paths, ambiguous steps,
   skipped numbered instructions.
2. NO VOLUME HIERARCHY. Spotify at ~31k/112k files already has ~4,000
   endpoints and ~4,600 findings; location_map.json will be megabytes. A
   model cannot ingest that. Efficiency needs a ranked front page plus
   stable IDs the model can page/request — not the complete index at once.
   The current design is honest but not efficient.
3. FOUR OVERLAPPING REPRESENTATIONS of the same data
   (static-analysis.json facts, facts.jsonl, location_map.json,
   workbook.location_ledger). Different models will read different ones and
   some will treat them as independent corroboration. Accuracy hazard;
   needs explicit "same evidence, different views" wording + a canonical
   precedence rule.
4. NO ENFORCED OUTPUT CONTRACT. ai_analysis.json / lead_ledger.json /
   closure_report.md are described in prose only. Nothing validates them,
   so finish_line is a suggestion, not a gate.
5. NO FEEDBACK LOOP. The model's closure report does not feed lead
   generation; every run starts from zero.
6. DEX STILL CAPPED (64MB androguard output cap), so a whole class of
   results never reaches the handoff at all.

## HANDOFF CONTRACT WORK — COMMITTED 2026-11-14 (6e8dcaf)
Implemented, tested and committed (see git log for the commit hash):
- NEW src/apkworkbench/analysis/surface/handoff.py: writes facts.jsonl
  (one compact object per fact, deterministic order, whole-file rewrite so a
  rerun cannot append duplicates) and location_map.json (index of every
  fact/finding/deduction with file:line, counts, artifact identity, and
  facts_jsonl_line pointers matching "surface/facts.jsonl line N" in the
  prompts). Atomic temp+fsync+replace writes.
- PATH-PREFIX FIX (real bug for the AI): analyzer evidence paths are
  tree-relative ("AndroidManifest.xml", "smali/...") while the prompts cite
  folder-relative ("apktool/smali/..."). handoff.py prefixes apktool/ but
  leaves scheme cites (endpoint:, permission:, sdk_root:, coverage:,
  route:, fact:) and absolute paths untouched. NOTE: this hardcoded prefix
  becomes WRONG under the per-bundle layout (D-1) and must become a
  parameter ("apktool/<component>/"). STATUS 2026-11-16: FIXED — the prefix
  is now a `tree_root` argument (default "apktool/", behavior unchanged).
- MOD src/apkworkbench/analysis/apk_surface.py: emits both files right
  after static-analysis.json; an OSError marks the artifact partial and
  records handoff_write_failed in diagnostics (never silent).
- MOD src/apkworkbench/analysis/surface/workbook.py: tool_outputs text now
  describes both files as always present; location_ledger gains additive
  tree_root="apktool/" + a note that scheme-prefixed cites are not paths.
- NEW tests/test_surface_handoff.py (6 tests): JSONL/fact order parity,
  line-number alignment, finding/deduction citations, locationless entries
  stay visible (has_location=false, never dropped), byte-identical rerun,
  and a driver-level test proving both files land beside
  static-analysis.json.
- State: 211 tests pass; ruff clean on all new/changed files (7 pre-existing
  ruff findings elsewhere are untouched: androguard_dex.py ISC004, unused
  imports/locals in older tests, dict-key repeat in test_final_run_report).
- Still NOT built: handoff folder/freeze step (D-2/D-3), volume hierarchy,
  schema gate, dry run. static-analysis.json was untouched by this commit so
  S8 parity still holds.

## CITATION-ROOT PARAMETERIZATION — DONE 2026-11-16 (D-1 step 2)
Behavior-neutral prerequisite for the per-bundle layout: the hardcoded
"apktool/" citation prefix is now a parameter. Defaults preserve the current
single-APK output byte for byte (all pre-existing tests pass unchanged).

Threaded as `tree_root` (keyword-only where the signature had `*`):
- surface/handoff.py: `_folder_relative`, `_locations`, `_fact_entry`,
  `_finding_entry`, `_deduction_entry`, `build_location_map`, `write_handoff`.
  `TREE_ROOT_PREFIX = "apktool/"` is now only the default value. The
  `how_to_verify` prose interpolates the root instead of hardcoding apktool/.
- surface/workbook.py: `build_workbook(result, *, tree_root="apktool/")`
  feeds `location_ledger.tree_root`.
- surface/serialize.py: `finalize_result(result, *, tree_root="apktool/")`
  passes through to build_workbook.
- analysis/apk_surface.py: `analyze_apk_surface(..., tree_root="apktool/")`;
  `finalize_result(result, tree_root=...)`.
- analysis/apk_surface.py driver (run_static_surface_analysis): derives the
  root from the layout instead of guessing —
  `citation_root = f"{decoded.relative_to(output_root).as_posix()}/"`.
  Today decoded = output_root/"apktool" so this is "apktool/"; under D-1 a
  component decodes to output_root/"apktool/<component>" and the same line
  yields "apktool/<component>/" with no further edit. Used at the
  analyze_apk_surface call, the finalize_result call and write_handoff.
- Tests: tests/test_surface_handoff.py::test_tree_root_parameter_prefixes_component_citations
  (asserts apktool/base/ prefixes for fact, finding and deduction cites) +
  tests/test_surface_serialize.py::test_workbook_tree_root_is_parameterized.

Verification: `.venv/bin/python -m pytest -q` -> 213 passed (~37s),
ruff clean on all six changed files.

Deliberately NOT done in this step: files were not moved into surface/;
final_run.py:368 and workspace.py:327 have no new-path fallback yet; nothing
frozen; prompts not edited; ai-memory/claudefix.txt (trust_decision note)
still SAVED ONLY / not implemented.

## RESUME HERE (pause point 2026-11-16; read this first)
1. Read in this order: INDEX.md (this file, especially CANONICAL DESIGN
   DECISIONS) -> appdev.txt §1 STATE + §14 decisions + §15 consumers ->
   todo.md (phase order) -> plan.txt phase ladder -> prompts/README_BUILD.md
   if touching the handoff. Working the NATIVE track instead: read
   native-plan.md first, then appdev.txt §4 (native knowledge).
2. Agreed operating rule: ONE PHASE AT A TIME. Finish it, stop, report the
   result; the user reviews before the next begins.
3. Phase order (details + exit criteria in todo.md):
   0. DONE: handoff writers committed (6e8dcaf); tests 211 green.
   0b. DONE 2026-11-16: citation-root parameterized (D-1 step 2); tests 213
       green. Committed + pushed as recorded in the commit log.
   1. NEXT — per-bundle workspace + freeze rework (D-1/D-2/D-3/D-4):
      results/<pkg>/<version>/<index_sha256>/, apktool/<component>/,
      surface/ + trufflehog/ + manifest/ + prompts + handoff.json +
      ai_analysis/attempt-01/, read-only freeze + hashes.sha256 +
      verify-workspace, consumer fallback for static-analysis.json.
      The citation-root parameter (last bullet of the old item 1) is DONE;
      what remains is the layout move + freeze + the two consumer fallbacks.
   2. Dry run of prompts 0..6 on one real bundle (use a single-APK app first;
      bundle handling is new, so do not stack unknowns).
   3. Fix only what the dry run proved (likely volume hierarchy, evidence
      precedence, output schema gate).
   4. Phase A ceilings done as STREAMING to disk, not deleting caps (box has
      3.8GB RAM; truncation would become OOM).
   5. Optional: single-pass trufflehog verified+unverified split (D-5).
   6. Phase D dossier, Phase E corpus correlation, Phase F per-run
      isolation — as needed. Phase C rewrite is CANCELLED (D-6).
4. Open decisions the next session must resolve before coding item 1:
   - LAYOUT (still open, one-line answer needed): put
     static-analysis.json / facts.jsonl / location_map.json under a real
     surface/ subdirectory (prompts 0/2 and workbook.py already promise it;
     recommended YES), and keep google-play-bundle.json at the bundle root
     (google_play.py:584, verification.py:202, final_run.py:364 expect it;
     recommended YES, which contradicts D-3's manifest/ wording).
   - per-artifact static-analysis.json aggregation at bundle level (D-1
     OPEN bullet) — proposal surface/artifacts/<sha256>/ + surface/bundle.json.
   - whether to migrate existing results trees or finalize them in place and
     only use the new layout for new runs (recommended: new runs only; the
     analyzer version gate already forces re-analysis of stale artifacts).
5. Known-good artifacts for replay: Antennapod before/after JSON at
   /tmp/opencode/antennapod-before.json and -after.json; benchmark harness
   /tmp/opencode/bench_sweep.py (300-file parity/speed check); Antennapod
   decoded tree under /tmp/opencode/ws/results/de.danoeh.antennapod/.
6. Current code/test facts: tests 213 green, analyzer 0.3.0, S8 perf 062973b.
7. Authorization context (user, 2026-11-14): the user has company
   authorization to implement this tool and scan Play APKs at will; the tool
   itself performs NO live validation — the terminal AI agent does all live
   verification. Do not frame scope/rules caveats as blockers, and do not
   add network probing to the tool.
8. Environment facts that constrain work: dev fixture workspace
   /tmp/opencode/ws is TMPFS (1.9GB/337MB free) — move to disk before batch
   work (D-8). Product default ~/APK-Workbench/workspace is on disk.

## COUNTERMEASURES MAPPED (why this folder reduces my failure modes)
- Context decay across sessions -> STATE + file map; no memory-only recall.
- Hallucination on specifics -> appdev.txt VERIFY-tag law + fixture-first.
- Schema breakage -> appdev.txt §15 consumers contract before edits.
- Drift/scope creep -> plan.txt phase ladder + notes in INDEX STATE.
- Non-determinism habits -> appdev.txt §16 tripwires.
- Speed-vs-accuracy tension -> PERFORMANCE LAW (plan.txt doctrine):
  actively seek speedups, accuracy/reliability always win; considered
  speed review recorded per phase in decisions log.
- Token inefficiency for AI consumer -> design laws in plan.txt §8B.
