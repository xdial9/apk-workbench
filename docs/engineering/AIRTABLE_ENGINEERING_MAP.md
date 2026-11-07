# Airtable Engineering Map

Airtable is the shared engineering coordination layer for APK WORKBENCH. This repository contains a versioned, human-readable snapshot of its architecture and evidence specifications; Airtable remains the live collaborative workspace.

- **Base:** APK Workbench — Engineering Map & Implementation Roadmap
- **Base ID:** appoG1faRDn2ztUOL
- **Tables:** 18
- **Records:** 286 at snapshot preparation (267 original audit records + 9 architecture specification records + 10 evidence schema records).
- **Initial repository inventory baseline:** commit 5256bd9b9ccdaa9a9834b72ea9c5802568d41088 on fix/package-file-validation.
- **Documentation branch baseline:** main commit 08f662632bd50ff3c69c9372eada3b3c320d32d4.

Find the live base in Airtable by its exact name or base ID. No direct base URL is published because the connector did not return a verified browser URL.

## Table inventory

| Table | Records at snapshot | Purpose |
|---|---:|---|
| Repository Files | 47 | Commit-pinned source inventory, blob IDs, file purposes and audit status |
| Components & Modules | 20 | Existing and proposed subsystem responsibilities |
| Functions & Interfaces | 29 | Major symbols, signatures and source mapping |
| Architecture & Dependencies | 27 | File relationships, dependencies and lineage |
| Application Data Flow | 15 | Current and proposed processing stages |
| Database & Evidence Models | 14 | Existing persistence models and proposed data entities |
| External Tools & Dependencies | 13 | Runtime tools, versions, licenses and adoption decisions |
| CLI Commands & Configuration | 10 | Commands, settings, defaults and error semantics |
| Analysis Engines & Extractors | 11 | Current analyzers and proposed extractor capabilities |
| Tests & CI Workflows | 11 | Test coverage and verification boundaries |
| Defects & Technical Debt | 13 | Confirmed defects, risks and remediation |
| Security & Reliability Assessment | 8 | Controls, evidence and reliability gaps |
| Architecture Decisions | 9 | Context, alternatives, rationale and consequences |
| Implementation Roadmap | 16 | Prioritized tasks, dependencies and acceptance criteria |
| Acceptance Criteria | 12 | Verifiable completion requirements |
| Release Readiness | 12 | Release gates and supporting evidence |
| Target Architecture Specification | 9 | Implementation-ready target design and interfaces |
| Evidence Schema Specification | 10 | Logical data entities, constraints, relationships and migration |

## How to use the mirror

- Treat GitHub as authoritative for source code and commit history.
- Treat the live Airtable base as the working engineering index, not as the runtime database.
- Keep repository paths and commit SHAs attached to findings about code; never refer to a file without its revision context.
- Update roadmap status only when the corresponding code or verification evidence exists.
- Do not mark a task Verified based only on a proposed design or mocked tests.
- When implementation changes the target design, update the Airtable decision and corresponding Markdown specification in the same work session.
- Keep mistakes, superseded decisions and abandoned approaches. Mark them superseded; do not erase the evidence of why the project changed direction.

## Snapshot files

- [Target Architecture](../architecture/TARGET_ARCHITECTURE.md)
- [Evidence Data Model](../architecture/EVIDENCE_SCHEMA.md)
- [Project History](../PROJECT_HISTORY.md)

## Scope boundary

Airtable stores engineering metadata only. It is not a production dependency of APK WORKBENCH and must not store APK binaries, raw scan output, secrets, credentials or user runtime evidence. The application will use local SQLite and content-addressed files for operational analysis data.

This Markdown is a curated snapshot, not a full API-level dump of every live Airtable cell. The base ID and table inventory identify the live mirror; architecture and evidence specifications are reproduced in full here so code work can proceed from a repository checkout without requiring Airtable access.
