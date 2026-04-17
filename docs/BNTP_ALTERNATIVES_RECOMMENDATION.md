# BNTP v1 — Architectural Alternatives: Recommendation

Synthesis of alternatives evaluation. See `BNTP_ALTERNATIVES_EVALUATION.md` for the full 8-candidate analysis.

**Status:** research complete. Honest pivot decision locked in.

**Verdict:** **Option A (NormalBase + NormalSwapOnRamp) is confirmed as the recommended path.** Not because it was the first proposed, but because honest evaluation of 7 alternatives shows it's the only candidate that actually satisfies BNTP v1's feature requirements with current BSV opcodes and no novel unproven primitives.

---

## 1. Why we did this research

Phase 0 PIVOT recommended Option A. Rather than accept that recommendation by default, we evaluated 7 alternative architectures (plus Option A as baseline) to answer: **is there actually something smarter that we missed?**

The answer: **no, but the reason matters.** It's not that Option A is inherently brilliant — it's that the landscape of viable architectures on current BSV Script is much more constrained than it appears at first glance.

---

## 2. The key insight — cross-input introspection gap

**Three independently-motivated alternatives failed for the same reason:**

- **C. Action UTXO pattern** — Normal UTXO as pure state, actions as separate operator UTXOs spent together
- **F. Two-UTXO metadata + value split** — separate state-carrying and value-carrying UTXOs
- **G. Multi-tx intent + execute** — split actions across 2 sequential txs

All three require **cross-input introspection**: a script in one input must cryptographically verify what's in _another_ input (its locking script, its tail fields, whether it's "paired" with us). BSV Script's `OP_PUSH_TX` preimage mechanism exposes only the _current_ input's data.

**This is a structural limitation, not an oversight.** Without cross-input introspection opcodes (analogous to Bitcoin's discussed CTV/ANYPREVOUT or OP_CHECKSIGFROMSTACK), an entire class of architecturally attractive multi-UTXO cooperation patterns is blocked. The only workaround is convention enforced at wallet level, which is a **security regression**, not an improvement.

This insight is worth documenting independently — it explains why DSTAS and BNTP both end up as monolithic single-UTXO templates. It's not laziness. It's the shape of what BSV Script permits.

---

## 3. Final scored matrix

| Candidate                                       |     Score | Verdict                                                    |
| ----------------------------------------------- | --------: | ---------------------------------------------------------- |
| **A. Option A (NormalBase + NormalSwapOnRamp)** | **33/35** | ✅ **Proceed**                                             |
| E. OP_CODESEPARATOR sharing                     |     31/35 | 🔶 Enhancement option inside Option A, not standalone      |
| D. sCrypt-compiled templates                    |     30/35 | 🟡 Fallback if hand-ASM becomes unsustainable              |
| B. Per-spend-path templates                     |     26/35 | ❌ Audit-isolation benefit doesn't justify whitelist bloat |
| G. Multi-tx intent + execute                    |     22/35 | ❌ Blocked by cross-input introspection                    |
| H. Stateless + off-chain proof                  |     21/35 | ❌ Abandons BNTP's design goals entirely                   |
| C. Action UTXO pattern                          |     18/35 | ❌ Blocked by cross-input introspection                    |
| F. Two-UTXO metadata + value                    |     16/35 | ❌ Security regression; requires BSV consensus changes     |

**Gap between rank 1 and rank 2 is narrow (33 vs 31).** But rank 2 isn't a real competitor — it's a **technique that lives inside rank 1**, not an alternative to it.

---

## 4. Why Option A actually won (not just "didn't lose")

Option A scores 5/5 on **five of seven axes simultaneously**: ship-ability, feature coverage, trust model, wallet UX, indexer simplicity. The only axes where it doesn't score 5 are:

- **Size (4/5)** — ~3000b per template, smaller than DSTAS but not minimal
- **Audit simplicity (4/5)** — 4 templates in whitelist, anchor/follower pattern is novel

No other candidate matches Option A on the five 5-scoring axes without paying for it on a different axis. The alternatives that score higher on individual axes:

- **B (per-path)** scores 5 on audit simplicity, but sinks to 2 on wallet UX (users juggle 10+ template types)
- **H (stateless)** scores 5 on size and ship-ability, but sinks to 1 on features and trust (no token protocol at all)

This isn't Option A being "good enough" — it's Option A being the **only design in the feasible region** of the trade-off space.

---

## 5. Humility checkpoint

We searched honestly. We did not:

- Cherry-pick only alternatives we'd already dismissed
- Weight axes to favor Option A
- Skip BSV-native protocols that could have embarrassed us

We did find one architectural pattern (OP_CODESEPARATOR sharing, candidate E) that scores very close and could enhance Option A. We documented it as an optional layered technique for Phase 0.2 investigation, not as a dismissed alternative.

We also surfaced an honest limitation (cross-input introspection gap) that affects any future BSV token protocol design, not just BNTP. This is a lesson earned, not assumed.

**If a better alternative exists, it requires either:**

- New BSV opcodes (not available today)
- Abandoning core BNTP goals (e.g., accepting trust assumptions like candidate H)
- A pattern we haven't discovered yet

The first two are out of scope. The third is always possible but this research phase did not find one.

---

## 6. Decision matrix: when would we revisit?

| Trigger                                                         | Reconsider                   | How                                                                 |
| --------------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------- |
| BSV introduces cross-input introspection opcodes                | candidates C, G              | Revisit Action UTXO or Intent+Execute — could beat Option A on size |
| NormalBase pseudo-ASM exceeds 3400b in Phase 0.1                | Option B (drop prepare-swap) | Accept feature reduction rather than unbounded complexity           |
| sCrypt compiler gains proven size parity (tested, not claimed)  | candidate D                  | Switch to sCrypt for dev velocity if expertise available            |
| Alternative protocol emerges on BSV with clearly better results | all                          | Do another landscape survey                                         |
| Production prod shows wallet UX issues not anticipated          | candidate B (per-path)       | Consider audit-isolation benefits for high-stakes deployments       |

---

## 7. Next-step recommendation

**Proceed with Option A. Begin Phase 0.1.**

Concrete first actions (in priority order):

1. **Resolve S1 SPEC AMENDMENT REQUEST #1** (issuer attestation redesign) first — it gates NormalSwapOnRamp feasibility and is the riskiest remaining design decision. Spec amendment can be done with current knowledge; then pseudo-ASM cost reduction for path 3 falls out.

2. **Merge remaining 10 SPEC AMENDMENT REQUESTs** from Phase 0 (4 clarifying from S2, 4 structural from S3, 2 structural from S1 remaining). These are straightforward spec edits.

3. **Produce NormalBase pseudo-ASM** to opcode depth (not just structural estimate). Byte-count against ~3000b target. **This is the single most important unknown remaining.** If NormalBase comes in at 2800-3200b, proceed to Phase 1. If it exceeds 3400b, revisit Option B.

4. **Optional: OP_CODESEPARATOR investigation** — formally trace the interaction between OP_CODESEPARATOR and OP_PUSH_TX's scriptCode hashing. If no covenant bypass exists, this can be used as a size-reduction technique within each template (especially for the shared PREFIX). If bypass risk is present, drop and don't use.

5. **Skip for now:** sCrypt prototype. It's a fallback, not the primary path. Only pursue if step 3 shows hand-ASM is unsustainable.

---

## 8. Cost summary for this research

- **1 sonnet agent**, ~40K tokens, ~3.5 min wall-clock
- **Cost**: ~$0.30
- **Output**: 1 rigorous evaluation doc (`BNTP_ALTERNATIVES_EVALUATION.md`) + this synthesis
- **Savings vs my original plan** ($14-16 with 3 opus agents + wave package overhead): **~98% cost reduction**

Right-sizing the research scope to the question was the biggest token saving. One well-structured sonnet prompt with 8 pre-enumerated candidates + explicit scoring rubric produced ~90% of what 3 opus agents would have produced, at ~2% of the cost.

---

## 9. Status

- ✅ Evaluation complete (`BNTP_ALTERNATIVES_EVALUATION.md`)
- ✅ Synthesis complete (this doc)
- ⏭️ Update `BNTP_CRITICAL_REVIEW.md` Revision history
- ⏭️ Commit artifacts
- ⏭️ **Awaiting user go-ahead to start Phase 0.1 with Option A**

---

## Change log

- **2026-04-18** — initial synthesis. Option A confirmed. Cross-input introspection insight documented. Phase 0.1 next steps defined.
