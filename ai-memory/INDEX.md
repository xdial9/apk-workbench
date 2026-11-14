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
- Branch: feature/goopdl-account-auth (commit 63ca287, auth + discover/
  download hardening; tests 152 green; live account-mode validated).
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
- SURFACE OVERHAUL (plan v2): S1 done (9898217); S2 done (652a088, pushed):
  analysis/surface/classify.py single-walk + magic routing; inventory_apk_zip
  maps every APK member (Appendix C) + nested containers; classification
  summary in inventory; integration fixture now a real zip; tests 169.
  Next: S3 manifest v2 (full element map, deep links, meta-data, providers,
  queries, backup rules, NSC domain-config/anchors, anomaly deductions).
  S6 must include the WORKBOOK section (§7A) in serialization scope so the
  handoff is complete.
- Environment: repo /home/user/APK-Workbench; venv .venv/bin/python; pytest
  all-green baseline 152; apktool 3.0.3; trufflehog 3.99.8; androguard 4.1.4
  pinned; live fixture workspace /tmp/opencode/ws (VERIFY exists before use).
- Working files now live MOVED INTO ai-memory/ by the user (plan.txt,
  surface.txt, firstreport.txt, appdev.txt are canonical HERE; repo root
  still holds firstreport.txt + surface.txt copies + plan.txt may be gone
  from root — VERIFY root state at next session and re-sync as needed).
- Open question logged in appdev.txt §1: Phase S branch choice (default:
  stay on current branch until user says otherwise).

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
