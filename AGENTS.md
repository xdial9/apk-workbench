# AGENTS.md — APK-Workbench

Repo: /home/user/APK-Workbench. Branch: feature/goopdl-account-auth.
Venv: .venv/bin/python. Tests: .venv/bin/python -m pytest -q
CORE IDENTITY

This program is a deterministic static surface scanner + handoff builder.
It never guesses, never hides a finding, never silently skips a file.
Every claim cites file:line evidence. Similarity is a hint, never a link.

The surface scanner IS the program. Everything else — acquire, decompile,
TruffleHog, reporting, reconciliation — exists to feed it or package it.
But the whole pipeline must run smoothly end-to-end. A scanner that works
in isolation is not a working program.
HARD RULES

    ONE TASK AT A TIME. Finish the prompt given, stop, report. Do not start the next phase.
    ONE PHASE AT A TIME. One bug / fix per prompt. Smallest change possible.
    NO REWRITE. Targeted, measured changes only. Do not refactor unrelated files.
    NO SEMANTIC CHANGE unless the prompt explicitly says so. Preserve all existing keys, outputs, and test behavior.
    NO PUSH without explicit instruction. Commit locally only if the prompt says to.
    NEVER run the full Spotify heavy case. NEVER work in /tmp/opencode/ws — it is TMPFS (1.9GB). Use disk workspace.
    NEVER delete a cap to fix truncation — that turns truncation into OOM on a 3.8GB box. Stream to disk instead.
    NEVER edit code until mapped and bug reproduced. Re-read code before editing; never edit from memory.
    DEDUCE FROM DATA, NEVER GUESS. If unsure, write "unverified".
    If a prompt path does not exist, write status.json with status + reason. Never leave a promised path absent.
    Every change needs a test. Every test run must be pasted in full.
    Show diff + tests after fix.
    End every response with the PASTE-BACK block defined in the prompt.

## 1A. CROWN JEWELS — 3, 4, 5 ARE THE PROGRAM

3, 4, 5 are the crown jewels. The job is not to list them, it is to map them.

3. SURFACE SCAN — breadth. Sweep every file in decoded APK: code, XML, assets, raw, resources. Answers: what exists?
4. DEX ANALYSIS — logic. Every DEX, every class, every method, every external ref, every internal call edge, every DEX string with callers, permission-to-API mapping. Answers: what does code do, and who calls whom?
5. NATIVE — hidden half. Every .so, every export, every import, every JNI entry, every native string. Answers: what does app do that Java never sees?

Collection alone does NOT unlock the program. Mapping does. If 3, 4, 5 just produce three separate lists, you still have three piles.

DEDUCTION MAPPING — REQUIRED for every finding in 3, 4, 5:
- Every DEX string must carry its xref callers, not just its value.
- Every finding must carry: location (file:line, per-component path), caller, callee, permission context, network context where determinable.
- Every native export must carry its JNI mapping to the Java method that calls it, or be marked unmapped_jni with a reason. Never leave it unmapped with no reason.
- Every call edge must be across DEX files and across components, not just within one DEX.
- Every secret must carry file + method that uses it if determinable, or usage_unverified if not.
- No finding in 3, 4, 5 passes without its links. Missing links = incomplete, fails reconciliation.
- Mapping is deduction from file:line evidence, never similarity, never guess. If a link cannot be proven, mark it unverified with reason, do not invent it.

The final AI must be able to trace end-to-end from this mapping: URL -> method -> caller chain -> entry point -> permission -> native call -> secret. If it cannot trace it, mapping is incomplete.

DATA PLANE LAW — OUTPUT IS FOR AI, NOT HUMAN

This pipeline writes for a universal AI, not a human reader.
The structured output during the pipeline is specifically to hand off to an AI model (preferably universal). That AI is the final tool call.

    Primary output is JSON / JSONL with stable schema. Same key = same meaning in every artifact, every run.
    No load-bearing fact lives only in HTML, Markdown prose, or terminal output. Terminal progress is ephemeral, for the operator while it runs. It is not data.
    HTML report, dossier.md, human summary: derived views only. Never the source the next stage reads.
    README.txt in a bundle is a 10-line bootstrap pointer only: start at 0.txt, then handoff.json, then surface/facts.jsonl + location_map.json. No analysis, no conclusions in README.
    The pipeline provides facts, findings, coverage, leads, indexes. It does NOT write narrative conclusions. The final AI does that in ai_analysis/.
    The AI writes ai_analysis/dossier.md and ai_analysis.json. The pipeline does not.

COMPLETENESS LAW — EMPTY MEANS EMPTY

    Empty means empty. Overflow means counted + sharded + coverage=partial. Never replace overflow with [].
    A list that looks like [] must mean the true count is zero. If the true count overflowed, preserve metrics.total_* counts, shard to disk as part-001.jsonl, part-002.jsonl, etc., set coverage to "sharded" or "partial", and add a diagnostic with shard count + total counts.
    Example of what NOT to do: Androguard 64MB cap that threw away the whole payload and returned external_method_references=[], metrics={}. That makes an AI infer "no API usage" from "too much API usage to fit."
    Every stage writes status.json with {status, counts, coverage, diagnostics}. Logs are not status.
    If a file is skipped (decode leftover, unreadable, too large, filtered), it must appear in the coverage ledger as skipped with a reason. Checked vs skipped must be different states, never both absent.
    TruffleHog: verified and unverified are separate outputs from one pass. Never drop unverified silently. If findings are [], the AI must be able to tell whether that means zero hints or N hints filtered.

## 6A. SHARD INDEX — AI MUST NOT HAVE TO READ ALL SHARDS

Sharding helps the pipeline but hurts the AI if the AI must read every shard to answer one question.

Every shard set must have an index file the AI can use without reading all shards:
- surface/shards-index.json, trufflehog/shards-index.json, dex/shards-index.json, etc., as applicable.
- Each index lists: shard file name, natural unit (DEX file / component / directory), counts in that shard (total findings, total methods, total strings, etc.), first/last keys or ranges, hash.
- Parent merges only counts + indexes + shard list, never full data.
- Final report must include shard indexes + total counts. AI reads index first, then reads only the shards it needs.
- If a shard set has no index, gate fails.

PIPELINE SMOOTHNESS

Each stage must run with no manual fix, no stale marker, no tmpfs workspace:
discover -> download -> verify -> decompile -> surface -> trufflehog -> report -> reconcile

Each stage must:

    Emit its own structured status.json
    Land its outputs in the bundle
    Be verifiable by verify-workspace
    Be idempotent / resumable where it is long-running

The AI does not read CLI output. It reads the bundle folder.
BUNDLE LAYOUT (Unit 1)

    Bundle root: results/<package_id>/<version_code>/<index_sha256>/ where index_sha256 is the run manifest index_sha256 (bundle_id), NOT the per-APK digest.
    Original APKs stay in downloads/<pkg>-<version_code>/, never moved.
    Decoded components: apktool/<component>/ e.g. apktool/base/, apktool/split_config.arm64_v8a/, one dir per component.
    Surface outputs under bundle: surface/static-analysis.json, surface/facts.jsonl, surface/location_map.json
    Citation root is per-component: derived as f"{decoded.relative_to(output_root).as_posix()}/" so it becomes apktool/<component>/ per component. location_map.json AND workbook.location_ledger must cite the real component path.
    Freeze: chmod evidence read-only: apktool/, surface/, trufflehog/, manifest/. Write hashes.sha256 over ALL frozen files.
    handoff.json at bundle root: schema/tool/prompt versions + hashes of key files + analyzer version + bundle_id.
    ai_analysis/attempt-01/ is the ONLY writable area after freeze. Everything else stays read-only.
    Missing stage => status.json in that stage dir with {status, reason}. Never leave a promised path absent.

## 7. 360 DEGREE WORKFLOW — 100% CHECKLIST

100% means 100% file-coverage, not runtime proof. Static analysis cannot prove what the app will do at runtime: reflection, dynamically loaded code, server-side logic, encrypted strings that only decrypt at runtime, native obfuscation. 100% means: we accounted for every file, preserved every string / method / finding in those files, mapped every link we could prove, and marked the rest unverified with reason. Do not promise runtime proof. Do promise file-coverage proof.

360 means full circle. No angle missed. Every run must cover ALL of these,
and prove it in coverage + counts. If an angle is not applicable (e.g. no native libs),
record it as "not_present: 0 files" — never leave it absent.

    0 DEG — ACQUIRE: discover, download, verify hash + signature + version.
    Original APKs stay in downloads/<pkg>-<version_code>/, never moved.
    45 DEG — MANIFEST: permissions, components, activities, services, receivers,
    providers, intent filters, deep links, features, SDK versions, libraries.
    90 DEG — DEX: every DEX file, every class, every method, every external reference,
    every internal call edge, every DEX string (URLs, domains, IPs, routes, headers),
    permission-to-API mapping. No DEX file skipped.
    135 DEG — NATIVE: every .so, every export, every import, every JNI entry,
    every native string, every native library dependency. No .so unaccounted.
    180 DEG — RESOURCES / ASSETS: every file in decoded APK, every XML, every asset,
    every raw file, every resource. Sweep must visit every file, not just code files.
    225 DEG — NETWORK SURFACE: every URL, domain, IP, route, header candidate,
    certificate / pinning indicator, WebView usage, network API usage.
    From DEX strings + native strings + manifest + resources, combined, not just one source.
    270 DEG — SECRETS: TruffleHog verified + unverified, see Section 8.
    315 DEG — COVERAGE / PROOF: every file accounted, every skip with reason,
    every error recorded, every stage status.json present, reconciliation complete == total.
    FULL CIRCLE — HANDOFF: bundle + handoff.json + final-report.json + hashes,
    frozen read-only, AI can consume it with zero project context.