BUILD NOTES (agent/user reference; NOT part of the handoff)
================================================================================
Purpose: first-draft numbered instruction chain for the final AI tool call.
Design decisions live in ai-memory/surface-plan-v2.md §7B + plan.txt
(PROGRAM IDENTITY + D2/D3). Status: DRAFT v1 — will be refined after first
live run against a real artifact folder.

FILES
  0.txt  master prompt (role, laws, deliverables, read-next pointer)
  1.txt  raw-map first (anti-anchoring) + AI creates its own memory bank in
         ai_analysis/memory/
  2.txt  tool-output integration + confirmed/disputed/missed cross-check
  3.txt  hint-tracing core work + per-lead work files + lead ledger triage
  4.txt  app-level deductions & correlations + risk synthesis
  5.txt  deliverables (dossier.md, ai_analysis.json schema inline, decision log)
  6.txt  adversarial closure + agents-free license + stop condition
  README_BUILD.md this file

CONSTRUCTION SPLIT (matches §7B plan):
  These 7 files are the STATIC template. Per-artifact generated content
  (interpolated by S6 serializer / Phase D):
   - location_map.json       index of every entry w/ file:line citations
   - surface/ + trufflehog/  tool outputs (per plan folder layout)
   - leads list              embedded in static-analysis.json deductions /
                             coverage; stage 2 merges with the AI's own
   - No leads .txt shard: leads come from generated files; template stays
     stable across versions (numbering fixed 0..6).

INTERPOLATION SLOTS (when pipeline emits handoff folders):
   - folder names: apktool/ surface/ trufflehog/ manifest/ are fixed names
     produced by run-folder layout (plan §8F). Interim Phase S paths differ
     (results/<pkg>/<ver>/<digest>/ roots). Serializer interpolates the
     folder key values in 0.txt if adapting interim layout.

KNOWN GAPS TO FIX IN NEXT DRAFT (ledger for ourselves, per tripweak culture):
  [ ] wording pass after first live run (what does a real model stumble on?)
  [ ] exact surface/ file names frozen at S6 completion (they may shift)
  [ ] sibling-version differential guidance currently references
      "workspace if accessible" — needs the final run-folder layout
  [ ] add explicit glossary entries for "location_map" schema as generated
  [ ] consider locale/content guidance for huge apps (paged reading hints)
  [x] 2026-11-14 acquisition wiring v0: bundle manifests carry provenance
      (discovered_via / run_id / run manifest + verification refs) and
      extra_files; catalog CSV carries discovery_channel/discovery_time;
      0.txt + 2.txt teach the handoff these locations; audit trail in
      ai-memory/acquisition-review.md (F1..F7).
