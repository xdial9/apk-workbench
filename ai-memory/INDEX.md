# AI-MEMORY — INDEX & STATE (read first, update often)
Owner: the agent. Purpose: active memory bank / map. Frequent reads and
writes required: no session starts without reading STATE; no state change
ends without updating STATE.

## FILE MAP (what lives here and what it's for)
- INDEX.md (this file)  : always-current state + protocol + file map.
- surface-plan-v2.md    : CANONICAL surface-analyzer overhaul plan (v2;
                          supersedes surface.txt's S-order; adds checkpoint
                          dumping + progress + AI-handoff shaping).
- appdev.txt            : Android domain knowledge + consumer contract +
                          drift tripwires + operational ritual (v2). Read at
                          every session start; §1 STATE MIRRORS this file.
- plan.txt              : master plan (doctrine, phase ladder S/A/B/C/D/E,
                          tool command specs, run-workspace design).
- surface.txt           : surface-analyzer line-by-line verdicts (0.2.0) +
                          execution order S-a..S-g.
- firstreport.txt       : full-codebase audit baseline (2026-11-13) +
                          overall opinion — stable reference, rarely changes.
- todo.md (when needed) : scratch session notes that graduate into files.

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

## STATE (as of 2026-11-14, updated by agent)
- Branch: feature/goopdl-account-auth (S8 perf commit 062973b; tests 205
  green; live account-mode validated).
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
  NEXT after S8: handoff contract — PARTIALLY DONE, UNCOMMITTED (writers for
  facts.jsonl + location_map.json exist in tree; folder assembly still
  missing; user has not approved committing). Then, in this order: prompt
  chain dry run (never executed, highest risk), volume hierarchy for
  large artifacts, Phase A ceilings, output schema gate, first user run.
  Read "HANDOFF READINESS ASSESSMENT" below before choosing.
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
- Working files now live MOVED INTO ai-memory/ by the user (plan.txt,
  surface.txt, firstreport.txt, appdev.txt are canonical HERE; repo root
  still holds firstreport.txt + surface.txt copies + plan.txt may be gone
  from root — VERIFY root state at next session and re-sync as needed).
- Open question logged in appdev.txt §1: Phase S branch choice (default:
  stay on current branch until user says otherwise).

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

## HANDOFF CONTRACT WORK IN THE TREE (UNCOMMITTED, decision pending)
Implemented but NOT committed, deliberately left for the user to choose
commit / keep-uncommitted / revert:
- NEW src/apkworkbench/analysis/surface/handoff.py: writes facts.jsonl
  (one compact object per fact, deterministic order, whole-file rewrite so a
  rerun cannot append duplicates) and location_map.json (index of every
  fact/finding/deduction with file:line, counts, artifact identity, and
  facts_jsonl_line pointers matching "surface/facts.jsonl line N" in the
  prompts). Atomic temp+fsync+replace writes.
- NEW path-prefix fix found while doing it: analyzer evidence paths are
  tree-relative ("AndroidManifest.xml", "smali/...") while prompts cite
  folder-relative ("apktool/smali/..."). handoff.py prefixes apktool/ but
  leaves scheme cites (endpoint:, permission:, sdk_root:, coverage:,
  route:, fact:) and absolute paths untouched. REAL BUG for the AI: every
  citation it received would have been off by one directory.
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
- NOT done: no dry run of the prompt chain, no volume hierarchy, no schema
  gate, no commit. static-analysis.json is untouched by design so S8 parity
  still holds.

## RESUME HERE (deliberate pause point, 2026-11-14 ~04:30)
1. Read ai-memory/INDEX.md -> appdev.txt §1/§15-17 -> todo.md -> prompts
   README_BUILD if touching the handoff.
2. Check the optimized Spotify heavy-case run:
   - command/log: /tmp/opencode/surface_spotify_optimized.log
   - launcher PID 42219 (likely gone if it finished); run
     c79180cf-01ab-4b2b-a507-4e238f24c1d1
   - durable marker: workspace results/runs/<run_id>/static-analysis-run.json
   - artifact: /tmp/opencode/ws/results/com.spotify.music/148387875/<digest>/
     static-analysis.json (4 APKs in the bundle)
   - if complete: record WALL_CLOCK_SECONDS + summary + status in INDEX §STATE
     and appdev §14; if missing: rerun the command captured in todo.md.
   - expected ~50-70 min from launch; do NOT confuse it with the aborted
     pre-optimization run (25,292/112,254 files in 2,351s), which is only a
     throughput baseline.
3. Work order: (a) handoff contract — PARTIALLY IMPLEMENTED, UNCOMMITTED
   (see "HANDOFF CONTRACT WORK IN THE TREE" above; files exist and tests
   pass, but the user has not approved committing). The prompts still say
   surface/facts.jsonl and surface/location_map.json while the driver writes
   results/<pkg>/<ver>/<digest>/facts.jsonl + location_map.json, so a handoff
   FOLDER assembly step is still missing even with the writers in place.
   (b) Phase A ceiling removal (androguard 64MB cap already proved harmful
   on a normal app); (c) prompt-chain dry run on one real artifact — this is
   the highest-risk unknown and should come before more code; (d) volume
   hierarchy (ranked front page + pageable IDs) because Spotify-scale
   location_map.json is not model-consumable; (e) enforced output schema for
   ai_analysis.json/lead_ledger.json; (f) first active user run.
4. Known-good artifacts for replay: Antennapod before/after JSON at
   /tmp/opencode/antennapod-before.json and -after.json; benchmark harness
   /tmp/opencode/bench_sweep.py (300-file parity/speed check).
5. Current code/test facts: S8 perf 062973b, tests 211 green (205 committed
   + 6 uncommitted handoff tests), analyzer 0.3.0.
6. Authorization context (user, 2026-11-14): the user has company
   authorization to implement this tool and scan Play APKs at will; the tool
   itself performs NO live validation — the terminal AI agent does all live
   verification. Do not frame scope/rules caveats as blockers, and do not
   add network probing to the tool.

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
