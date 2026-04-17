# BNTP Phase 0 — Pseudo-ASM Wave

**Status:** active. Wave package for pre-implementation validation of BNTP v1 core design assumptions.

**Package path:** `docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/`

## Goal

Validate three load-bearing assumptions of BNTP v1 single-variant design before any template implementation begins. Produce three design artifacts that gate proceeding to Phase 1 (skeleton mint + transfer + redeem).

The three artifacts together answer: _can we ship BNTP v1 as currently specified, or must we pivot?_

## Core Decision

**Proceed or pivot** decision after Phase 0 completes. Pivot means scope reduction (e.g., K-merge capped at 2 instead of 4) or redesign (e.g., different commitment scheme).

Phase 0 outputs are **design documents only** — no code, no template deployment. Implementation begins in Phase 1 after gates pass.

## Scope

**In-scope:**

- Pseudo-ASM for `Normal` template (single variant, supports K ∈ [2, 4] merge)
- Formal write-up of whitelist commitment scheme soundness
- Concrete anchor/follower position-determination algorithm with security argument
- Gate-check of all three against BNTP_CRITICAL_REVIEW.md §5.1

**Out-of-scope (Phase 1+):**

- `Frozen` template pseudo-ASM
- `SwapReady` template pseudo-ASM
- `Contract` template pseudo-ASM
- Actual template implementation (`src/bntp/templates/*.ts`)
- SDK builders
- Conformance vectors

## Core Rules

1. **No implementation code.** Phase 0 is pure design docs. If an agent starts writing TypeScript, redirect.
2. **Single-variant design is fixed.** Normal template has no N-2/N-4/N-8 split. Merge accepts K ∈ [2, 4] via `followerCount` push.
3. **Whitelist is 3 templates (96b block).** No reference to 5-template 160b layout.
4. **Tail is 145b fixed.** seriesId(32) + tokenId(32) + redemptionPkh(20) + issuerPkh(20) + flags(1) + freezeAuth(20) + confiscAuth(20). See BNTP_SERIES_V1_SPEC.md §5.4.
5. **No cross-slice file writes.** S1 owns only its target doc, same for S2 and S3. If something doesn't fit, surface as blocker, don't bleed into other zones.
6. **Cite the spec.** Every non-obvious design choice must reference a section of BNTP_SERIES_V1_SPEC.md.
7. **Explicit unknown-marker.** If an answer requires information not in the spec, write `**OPEN QUESTION:** ...` — do not invent.

## Ownership Zones

| Zone ID | Target doc                                         | Owner            | Forbidden                   |
| ------- | -------------------------------------------------- | ---------------- | --------------------------- |
| S1      | `docs/BNTP_TEMPLATE_NORMAL_ASM.md`                 | slice S1 agent   | any other doc write         |
| S2      | `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md`          | slice S2 agent   | any other doc write         |
| S3      | `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`           | slice S3 agent   | any other doc write         |
| W0      | `docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/*` | operator (local) | slice agents must not touch |

Spec docs (`BNTP_SERIES_V1_SPEC.md`, `BNTP_CRITICAL_REVIEW.md`) are READ-ONLY during Phase 0. If a slice needs to correct the spec, surface as a `**SPEC AMENDMENT REQUEST:**` note in its own doc, not an edit.

## Wave Ledger

| slice    | zone lead | subagent_type   | model | status           | depends_on | validation                                                                                                                                                              | done_when                                        |
| -------- | --------- | --------------- | ----- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| W0       | operator  | —               | —     | in_progress      | —          | quality gate §4.6 playbook                                                                                                                                              | 3 package files exist and committed              |
| S1       | agent     | general-purpose | opus  | **done (PIVOT)** | W0         | body ≈ **4640b** (2× budget); all 6 paths specified; 5 OPEN QUESTIONs; 3 SPEC AMENDMENT REQUESTs                                                                        | doc at `docs/BNTP_TEMPLATE_NORMAL_ASM.md`        |
| S2       | agent     | general-purpose | opus  | **done (PASS)**  | W0         | 5/5 claims defended; 4/4 spec attack surfaces addressed; 11 new surfaces enumerated, 0 unmitigated; 4 non-breaking SPEC AMENDMENT REQUESTs (clarifications)             | doc at `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md` |
| S3       | agent     | general-purpose | opus  | **done (PASS)**  | W0         | 7/7 attacks defended (A1-A7); 5/5 edge cases covered; 4 SPEC AMENDMENT REQUESTs (input contiguity, all_outpoints separation, followerCount cross-check, BIP143 offsets) | doc at `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`  |
| Gates    | operator  | —               | —     | **done (PIVOT)** | S1, S2, S3 | G1=PIVOT (size), G2=PASS, G3=PASS; overall=PIVOT                                                                                                                        | verdict in `evidence/closeout.md`                |
| Closeout | operator  | —               | —     | **done**         | Gates      | `audits/A1.md` + `evidence/closeout.md` written; commit pending                                                                                                         | files exist, awaiting commit + pivot decision    |

## Phase 0 Gates (from BNTP_CRITICAL_REVIEW.md §5.1)

**G1 — Normal body size:**

- PASS: estimated body (PREFIX + WHITELIST + SUFFIX + body marker) ≤ 2400b
- PIVOT: 2400 < size ≤ 2800b — reduce features (drop prepare-swap from Normal, require separate template)
- ABORT: size > 2800b — savings vs DSTAS vanish, design не работает

**G2 — Whitelist commitment soundness:**

- PASS: formal argument shows (a) no self-reference loop, (b) variant confusion blocked, (c) cross-series spoofing blocked, (d) whitelist-byte spoofing blocked
- PIVOT: one minor gap identified with mitigation path
- ABORT: fundamental flaw (e.g., commitment scheme doesn't actually commit what it claims)

**G3 — Anchor/follower security:**

- PASS: algorithm makes position-determination deterministic; shuffled-input attacks provably fail; follower cannot be spent outside anchor-led merge
- PIVOT: position-check requires extra constraint (e.g., "max 4 non-funding inputs") — add to spec
- ABORT: no secure algorithm found without breaking anchor/follower pattern → fallback to 2-input merge only (K=2 hard limit)

## Definition of Done

Phase 0 is DONE when:

1. Three target docs exist (`docs/BNTP_TEMPLATE_NORMAL_ASM.md`, `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md`, `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`).
2. Each doc passes its corresponding gate (G1/G2/G3) with explicit PASS/PIVOT/ABORT verdict.
3. `audits/A1.md` written with what landed, what validated, what residuals remain.
4. `evidence/closeout.md` written with final verdict on proceed-to-Phase-1.
5. Master ledger above updated with final statuses.

Phase 0 is NOT done if:

- Any slice returned `**OPEN QUESTION:**` markers that block its gate check.
- Gate verdict is ABORT for any of G1/G2/G3 → pivot plan required before Phase 1.
- Docs written but not committed.

## Delivery Notes

Commit hashes will be recorded here after each milestone:

- Wave package docs-only commit: _(pending)_
- S1 Normal ASM commit: _(pending)_
- S2 Whitelist proof commit: _(pending)_
- S3 Anchor algorithm commit: _(pending)_
- Closeout commit: _(pending)_

## Next Step Pointer

See `slices.md` for per-slice briefs.
See `launch-prompt.md` for executor handoff prompt (if re-running in fresh session).
