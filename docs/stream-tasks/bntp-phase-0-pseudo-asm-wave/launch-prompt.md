# BNTP Phase 0 — Launch Prompt

Executor handoff prompt. Paste this into a fresh session to resume/restart Phase 0 execution.

## Mission

Execute Phase 0 of BNTP v1 (single-variant design) as wave package. Produce three design docs, gate-check them, write closeout artifacts. No code — docs only.

## Package path

`/Users/imighty/Code/dxs-bsv-token-sdk/docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/`

## Constraints

1. **Read-only spec.** `BNTP_SERIES_V1_SPEC.md` and `BNTP_CRITICAL_REVIEW.md` are the source of truth. Do not edit them during Phase 0. Use `**SPEC AMENDMENT REQUEST:**` markers inside slice docs if amendments are needed.
2. **Disjoint file ownership.** Each slice writes exactly one target doc. No cross-slice file writes.
3. **Single-variant Normal.** No Normal-2 / Normal-4 / Normal-8 split — one Normal template supports K ∈ [2, 4] merge via explicit followerCount push.
4. **Whitelist is 96b, 3 hashes.** Do not reference the earlier 160b / 5-hash layout.
5. **Tail is 145b fixed.** See spec §5.4.
6. **No DSTAS bridge.** Do not reference migration, interop, or bridging with DSTAS.
7. **No TypeScript code.** Phase 0 is design docs only.

## Required execution order

1. **Verify wave package exists:**
   - `ls docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/{master.md,slices.md,launch-prompt.md}`
   - If any missing → recreate per playbook
2. **Commit wave package docs-only** if not already committed:
   - `docs(bntp): add phase-0 pseudo-asm wave`
3. **Launch three parallel agents** via single message with three Agent tool calls:
   - S1: `general-purpose`, model `opus`, brief per `slices.md` §S1
   - S2: `general-purpose`, model `opus`, brief per `slices.md` §S2
   - S3: `general-purpose`, model `opus`, brief per `slices.md` §S3
4. **Integrate each result** as it returns:
   - Read agent output → verify target doc exists → update master ledger row
5. **Run gate checks** G1, G2, G3 against slice outputs:
   - G1 (Normal body size ≤ 2400b) — read S1 doc, sum byte counts, verdict
   - G2 (Whitelist soundness) — read S2 doc, verify 5 claims + 4 attack surfaces addressed
   - G3 (Anchor/follower security) — read S3 doc, verify 5 attacks traced, all edge cases covered
6. **Write closeout artifacts:**
   - `audits/A1.md`
   - `evidence/closeout.md`
7. **Commit per milestone** (one commit per slice ideally):
   - `docs(bntp): add Normal pseudo-ASM (phase 0, s1)` → S1
   - `docs(bntp): add whitelist commitment proof (phase 0, s2)` → S2
   - `docs(bntp): add anchor/follower algorithm (phase 0, s3)` → S3
   - `docs(bntp): phase 0 closeout + audit` → closeout

## Validation

### Per-slice

| Slice | Check command / method                                                                                        |
| ----- | ------------------------------------------------------------------------------------------------------------- |
| S1    | Read `docs/BNTP_TEMPLATE_NORMAL_ASM.md` — confirm body size total reported and ≤ 2400b, 6 spend paths present |
| S2    | Read `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md` — confirm 5 claims + 4 attack surfaces                         |
| S3    | Read `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md` — confirm 5 attack scenarios (A1-A5) traced                     |

### Gates (from BNTP_CRITICAL_REVIEW.md §5.1)

- G1 PASS: body ≤ 2400b
- G2 PASS: commitment scheme sound against all enumerated attacks
- G3 PASS: algorithm secure, no open attack succeeds

## Closeout requirements

`docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/audits/A1.md` contains:

- What landed (list of files created, brief description of each)
- What validated (gate checks, which passed / pivoted / aborted)
- What residuals remain (open questions, spec amendments requested)

`docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/evidence/closeout.md` contains:

- Final verdict: **PROCEED to Phase 1** OR **PIVOT** (with concrete pivot plan) OR **ABORT BNTP v1**
- Key files and their role
- Summary behavior (what Phase 0 proved and what it didn't)
- Honest residuals for Phase 1 to absorb

Update `master.md` ledger with final statuses and commit hashes. Update `BNTP_CRITICAL_REVIEW.md` Status log with Phase 0 outcome.

## Commit/report expectations

After wave is closed:

- All slice docs committed under `docs/` (not under `docs/stream-tasks/`)
- `master.md` `Delivery Notes` section populated with commit hashes
- `audits/A1.md` and `evidence/closeout.md` committed as final Phase 0 commit
- Working tree clean

Report to user with compact closeout update:

```
Result: Phase 0 <PROCEED | PIVOT | ABORT>.
Zones done: W0, S1, S2, S3, Gates, Closeout.
Validation: G1=<result>, G2=<result>, G3=<result>.
Residuals: <real remaining items only, or 'none'>.
Ledger: master.md and closeout artifacts updated.
```

## Re-entry note

If session dies mid-execution:

1. Read `master.md` ledger — identify last completed zone
2. Read `slices.md` for remaining slice briefs
3. Resume from first `todo` or `in_progress` zone
4. If a slice doc exists but seems incomplete, treat as `stale` — read content, decide: extend via SendMessage (if original agent still recently-ended) or restart via new Agent with `slices.md` brief
