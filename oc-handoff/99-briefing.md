# OC-Handoff Briefing (99-briefing.md)

NOTE: AGENTS.md requests this file at `/home/user/oc-handoff/99-briefing.md`.
That path is absent and unwritable in this environment (`/home/user` does not
exist; session user is `dial9`). Written here instead so the promised path
exists inside the bundle workspace.

## State (as of 2026-11-17, P5 completion)
- Branch: feat/native-elf-reader; main == origin/main as of 2026-11-16 push.
- P0–P4 committed (scanner truth plane, identity, resources, links/entry points).
- P5 detection breadth DONE in worktree (this phase, pending commit).

## P5 deliverables (this phase)
- CODE_RULES 19 -> 29: added certificate_pinning_present,
  certificate_pinning_bypass, keystore_credential_access,
  sql_string_concatenation, path_traversal, intent_redirection, overlay_window,
  clipboard_access, accessibility_service, root_emulator_detection,
  exported_provider_risk, task_hijacking (12 ids, one of which — exported
  provider risk — is broader than the existing file_provider_exported).
  dynamic dex loading + native exec were already covered by dynamic_code_loading
  + process_execution (verified by grep before adding anything new).
- docs/rules.md: rule catalog with severity, rationale, false-positive
  conditions, one section per rule.
- D2 closed: packed_indicator fact now carries evidence (the dynamic-code-
  loading finding's path:line + blob cite); deduction cites the same findings.
- D3 closed: obfuscation_metric fact now carries evidence (first short-name
  smali path); deduction cites the short-name smali paths.
- D9 closed: endpoint/route findings roll up per normalised pattern
  (`_endpoint_pattern` / `_path_pattern` -> `{id}` for numeric/UUID/hex-long
  segments) with occurrence_count + bounded citation sample (first 10 + flag);
  facts.jsonl and the endpoint facts keep EVERY occurrence (data-plane loss
  is zero; findings-layer noise reduction only).
- Tests: +24 positive+negative fixtures in tests/test_surface_sweep.py.
- 365 tests green (was 341). No regressions.

## Commits
- P5 commit: <hash pending — commit after this briefing is written>.

## Next step
- P6 Containers and packed code: extract all code-bearing members
  (.dex/.jar/.apk/nested zips), stream + bound, feed to the DEX analyzer with
  `container!member` citations. Scanner-plan.md §P6 has the detail.

## Open decisions / unverified
- D5/D6/D7/D10/D12/D13/D14/D15/D17/D19/D20/D21 remain open per ledger.
- /home/user/oc-handoff/99-briefing.md path unavailable in this environment
  (noted above); this file is the substitute.
