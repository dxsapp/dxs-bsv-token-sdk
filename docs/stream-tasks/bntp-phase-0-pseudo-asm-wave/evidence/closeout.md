# BNTP Phase 0 — Closeout & Verdict

**Date:** 2026-04-17
**Wave:** `bntp-phase-0-pseudo-asm-wave`
**Final verdict:** 🟡 **PIVOT** (not PROCEED, not ABORT)

## Final verdict

**PIVOT to Phase 0.1 before Phase 1.**

Core cryptographic primitives validated sound. Script size budget unrealistic as specified — requires product decision on scope reduction before implementation begins.

Three concrete pivot options, in order of preference:

### Option A (recommended): Split + rebaseline

1. Split `Normal` → `NormalBase` (paths 1, 2, 4, 5, 6) + `NormalSwapOnRamp` (path 3 only).
2. Rebaseline per-template body budget to ~3000b (was 2400b).
3. Whitelist grows from 3 → 4 templates (NormalBase, NormalSwapOnRamp, Frozen, SwapReady). WHITELIST block 96b → 128b in every template.
4. Update `BNTP_SERIES_V1_SPEC.md` §3, §5.3, §12 accordingly.
5. Accept SPEC AMENDMENT REQUESTs from S1/S2/S3 (11 total, see `audits/A1.md`).
6. Proceed to Phase 1 skeleton (Contract + NormalBase + Redeem) with 4-template whitelist.

Trade-offs:

- ✅ Smallest scope change to proven-sound design.
- ✅ Swap/DEX flow still supported (just via dedicated on-ramp template).
- ❌ +1 template to audit (4 vs 3).
- ❌ Larger whitelist (128b vs 96b) adds ~32b per UTXO.
- ❌ Size savings vs DSTAS 1.0.4 reduce from −28% Normal to ~−19% NormalBase.

### Option B: Drop prepare-swap from protocol v1

1. Remove prepare-swap / SwapReady entirely from BNTP v1 scope.
2. Normal template carries only paths 1, 2, 4, 5, 6 → ~3200b body. Still over original 2400b, but closer.
3. Whitelist: Normal + Frozen = 2 templates. WHITELIST 64b.
4. DEX-compat deferred to BNTP v2.

Trade-offs:

- ✅ Smallest protocol surface; fastest to ship.
- ✅ Smallest whitelist; simplest commitment.
- ❌ **Loses DEX-compatibility story — one of BNTP's main value propositions vs DSTAS.**
- ❌ Users wanting swap must use off-chain escrow / external protocol.

### Option C: ABORT BNTP v1, return to drawing board

1. Accept that single-template designs on BSV Script are fundamentally too expensive for rich feature sets.
2. Investigate alternative approaches (e.g., per-spend-path separate templates with inter-template transitions, sCrypt-compiled templates, etc.).

Trade-offs:

- ❌ Discards 4 weeks of design work.
- ❌ No concrete alternative in hand.
- ✅ Honest admission that constraint is real.

**Recommendation: Option A.** It preserves the proven-sound primitives, delivers DEX-compatibility, and has a clear implementation path. The per-template budget increase to ~3000b is honest — BNTP's savings vs DSTAS come more from state discrimination (Frozen −70%, SwapReady −46%) than from a uniformly smaller Normal.

## Key files and their role

| File                                              | Role                                                                                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `docs/BNTP_SERIES_V1_SPEC.md`                     | Protocol spec — requires Option A updates (§3 template catalog → 4 templates; §12 size estimates; SPEC AMENDMENTs from A1 §3.1) |
| `docs/BNTP_CRITICAL_REVIEW.md`                    | Living design review — Phase 0 outcome to be logged in §8 Revision history                                                      |
| `docs/BNTP_TEMPLATE_NORMAL_ASM.md`                | S1 deliverable — concrete pseudo-ASM + size ledger + pivot rationale                                                            |
| `docs/BNTP_WHITELIST_COMMITMENT_PROOF.md`         | S2 deliverable — soundness proof of commitment scheme                                                                           |
| `docs/BNTP_ANCHOR_FOLLOWER_ALGORITHM.md`          | S3 deliverable — position-determination algorithm + attack analysis                                                             |
| `docs/BNTP_EXECUTION_PLAYBOOK.md`                 | Operator playbook for parallel agent execution (proved out in this wave)                                                        |
| `docs/stream-tasks/bntp-phase-0-pseudo-asm-wave/` | This wave package (master, slices, launch-prompt, A1 audit, closeout)                                                           |

## Summary behavior

Phase 0 as executed proved:

1. **Parallel agent orchestration works** — 3 opus agents delivered 3 rigorous design docs in ~5 minutes wall-clock with zero file collisions and clean per-slice closeouts.
2. **Whitelist commitment scheme is formally sound** — can be trusted as the foundation for closed forward state invariant.
3. **Anchor/follower algorithm is secure** — 7/7 attacks defended, position determination cryptographically anchored to hashPrevouts.
4. **Single-template all-paths Normal design does not fit in 2400b budget** — ~4640b actual, ~3600b optimized floor, recommended rebaseline to ~3000b with scope split.

Phase 0 as executed did NOT prove:

- That any specific template size target is achievable (we learned the 2400b target was unrealistic — need to set a new one based on Option A/B/C choice).
- That issuer attestation mechanism works as currently drafted (S1 surfaced a spec gap: CHECKSIG-over-arbitrary-hash doesn't exist natively in BSV Script; needs redesign).
- That complete Phase 1 scope is achievable — that depends on pivot choice.

## Honest residuals (to absorb into next phase)

1. **Spec amendments (11 total)** need to be reviewed and merged into `BNTP_SERIES_V1_SPEC.md` before Phase 1 starts. 4 are clarifications (S2), 7 are design/structural (S1×3, S3×4).
2. **Pivot decision** (Option A/B/C) must be made by human reviewer. Cannot be deferred; all Phase 1 work branches on this.
3. **Issuer attestation mechanism** requires explicit design round — current spec §9.4 is unimplementable as drafted. S1 SPEC AMENDMENT REQUEST #1 proposes a null-data output encoding that sits inside the normal preimage covenant.
4. **Normal unlocking format** — tuple form insufficient; should be full candidate scripts (S1 SPEC AMENDMENT REQUEST #2).
5. **Input layout invariant** — BNTP inputs contiguous at 0..K-1, funding strictly at K (S3 SPEC AMENDMENT REQUEST #1). Should be normative in spec.

## Next steps (gated on pivot decision)

If **Option A** chosen:

- Phase 0.1 (~1 week): spec amendments merged, new NormalBase/NormalSwapOnRamp template boundaries designed, whitelist scheme updated to 4 templates.
- Phase 1 (~2-3 weeks): pseudo-ASM → impl → conformance vectors for Contract + NormalBase + Redeem.

If **Option B** chosen:

- Phase 0.1 (~3 days): spec amendments merged, SwapReady removed from spec, whitelist reduced to 2 templates.
- Phase 1 (~2 weeks): Contract + Normal (no swap) + Redeem.

If **Option C** chosen:

- Research phase (~2-4 weeks): investigate alternative architectures.
- BNTP v1 spec archived as research artifact alongside DSTAS.

## Wave closeout discipline

- ✅ All 3 slices completed with explicit gate verdicts
- ✅ `audits/A1.md` written
- ✅ `evidence/closeout.md` written (this file)
- ✅ `master.md` ledger updated with final statuses
- ⏭️ `BNTP_CRITICAL_REVIEW.md` Status log to be updated
- ⏭️ Commit: slice docs, wave package, closeout artifacts
- ⏭️ User decision on pivot Option A/B/C pending

## Verdict restated

**🟡 PIVOT.** Core primitives sound. Scope reduction required before Phase 1. Recommended Option A: split prepare-swap into dedicated template, rebaseline budget to ~3000b. Human decision needed to proceed.
