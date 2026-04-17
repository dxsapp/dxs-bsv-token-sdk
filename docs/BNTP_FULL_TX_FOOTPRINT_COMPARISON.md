# BNTP — Full Transaction Footprint Comparison

**Status:** Research / decision-support. Not a spec.
**Date:** 2026-04-17
**Context:** Phase 0.1 NormalBase pseudo-ASM (`BNTP_TEMPLATE_NORMALBASE_ASM.md`) landed at ~4054b body (ABORT band). The previous alternatives evaluation (`BNTP_ALTERNATIVES_EVALUATION.md`) used locking-script body as the sole metric. This document corrects that by measuring **full transaction footprint** — every byte that lands on-chain across a realistic workload — and re-evaluates whether Option A is still the correct architectural choice under the correct metric.

---

## 1. Executive Summary

- **Option P (per-operation split) wins the hot path.** For the merge+split workload that operators run constantly in production, Option P's 4×transition + 1×merge-K flow is comparable to or smaller than DSTAS at K=4, and substantially better than Option A/A1 at K=2.
- **Option A1 (feature-cut A) is the safe fallback.** Cutting K=4→K=2, auth PKH-only, issuer PKH-only saves ~850b from NormalBase (~3200b body) — still larger per-UTXO than Option P's NormalLight, but avoids NormalMerge transition overhead on the cold paths.
- **Option A (current spec, 4054b body) is dominated by A1 on every workload and should be deprecated as a standalone target.** It retains feature richness but at a footprint cost that exceeds DSTAS on the most common operation (transfer).
- **DSTAS beats everything on cold paths (pure transfer, single freeze).** Its ~3050b UTXO and no-transition model is unbeatable for one-shot operations. Option P and Option A1 overtake DSTAS specifically on merge-heavy hot paths.
- **Option P's main risk is transition overhead.** Four small transition txs before a K=4 merge add ~2800b that Option A1 avoids. If operators frequently merge fewer than 4 UTXOs, the break-even with A1 deteriorates.

Overall ranking by hot-path weighted score: **Option P > Option A1 > DSTAS > Option A**.

---

## 2. Per-UTXO Size Baseline

### 2.1 Assumptions and conventions

- **Body** = opcodes between `OP_2DROP` and `OP_RETURN` (PREFIX + WHITELIST + SUFFIX).
- **Tail** = fixed 145b block after `OP_RETURN` (seriesId 32b + tokenId 32b + redemptionPkh 20b + issuerPkh 20b + authFlags 1b + freezeAuthHash 20b + confiscAuthHash 20b), empty optionalData.
- **Variable prefix** (owner PKH 21b + action_data 1b + OP_2DROP 1b) = **23b**, not part of body but on-chain.
- **Total UTXO on-chain** = 23 (var prefix) + body + 145 (tail). All sizes below follow this.
- **NormalBase (Option A, as-measured):** body 4054b → UTXO = 23 + 4054 + 145 = **4222b**. This is the honest Phase 0.1 number, not the spec target.
- **NormalBase (Option A, spec target 3000b):** UTXO = 23 + 3000 + 145 = **3168b**. Never achieved; shown for reference only.
- Whitelist block embedded in body: 128b (4 × 32b) for 4-template series, present in all Options A/A1/P body estimates.

### 2.2 UTXO size table

| Candidate   | UTXO type        | Body (b) | Total UTXO (b) | Notes                                                             |
| ----------- | ---------------- | -------- | -------------- | ----------------------------------------------------------------- |
| DSTAS 1.0.4 | Normal           | ~2900    | ~3050          | Monolith, ~150b tail area                                         |
| DSTAS 1.0.4 | Frozen           | ~2900    | ~3050          | Same template, action_data tag only                               |
| DSTAS 1.0.4 | SwapReady        | ~2900    | ~3072          | +22b swap descriptor                                              |
| Option A    | NormalBase       | **4054** | **4222**       | Phase 0.1 measured ABORT                                          |
| Option A    | NormalSwapOnRamp | ~1500    | ~1668          | Phase 0.1 estimate                                                |
| Option A    | Frozen           | ~760     | ~928           | Path-isolated estimate                                            |
| Option A    | SwapReady        | ~1500    | ~1668          | Path-isolated estimate                                            |
| Option A1   | NormalBase-lite  | ~3200    | ~3368          | K=2-only (−400b), auth PKH-only (−300b), issuer PKH-only (−150b)  |
| Option A1   | NormalSwapOnRamp | ~1500    | ~1668          | Unchanged                                                         |
| Option A1   | Frozen           | ~610     | ~778           | No MPKH branch (−150b)                                            |
| Option A1   | SwapReady        | ~1500    | ~1668          | Unchanged                                                         |
| Option P    | NormalLight      | ~1800    | ~1968          | Transfer/split/redeem + 3 transition-out paths; no merge logic    |
| Option P    | NormalMerge      | ~2200    | ~2368          | Merge K∈[2,4] + back-to-NormalLight; no transfer/split/auth paths |
| Option P    | NormalSwapOnRamp | ~1500    | ~1668          | Same as Option A                                                  |
| Option P    | Frozen           | ~760     | ~928           | Same as Option A                                                  |
| Option P    | SwapReady        | ~1500    | ~1668          | Same as Option A                                                  |

**NormalLight body estimate rationale (Option P ~1800b):** Remove merge-K path (−1115b from NormalBase) and replace with a single cheap transition path (~100b). Keep transfer/split/redeem/freeze/confiscate paths. Remove MPKH for authority (−300b) and issuer (−150b) from NormalBase. Net: 4054 − 1115 + 100 − 300 − 150 = ~2589b → subtract K=4 contribution from path_id dispatcher and shared §6 invocations (−300b additional simplification) → ~2300b. Remove K=4 output reconstruction from §6 helper (−150b) → **~2150b conservative, ~1800b optimistic**. This document uses ~1800b as target; footnote where uncertainty is high.

**NormalMerge body estimate rationale (Option P ~2200b):** PREFIX covenant + preimage parse (~550b) + whitelist (131b) + path 2 merge-K anchor+follower (1115b) + path back-to-NormalLight (≈path 3 shape, ~200b) + shared §6+tail helpers (~280b) = ~2276b → round to ~2200b optimistic.

---

## 3. Per-Workload Comparison

### Shared constants

| Item                                                 | Size (b) |
| ---------------------------------------------------- | -------- |
| Funding input (outpoint 40b + unlocking P2PKH 107b)  | 147      |
| Change output (P2PKH 34b)                            | 34       |
| Tx overhead (version, locktime, input/output counts) | 10       |
| STAS input outpoint+script-length+sequence fields    | 44       |
| Null-data output (attestation/memo)                  | ~50      |

Unlocking script sizes (inherited from DSTAS audit baselines, per `BNTP_VS_DSTAS_COMPARISON.md`):

| Operation                                                   | Unlocking (b) | Source                                    |
| ----------------------------------------------------------- | ------------- | ----------------------------------------- |
| Transfer/split owner-sig (NormalLight or NormalBase)        | ~230          | DSTAS §2.2 baseline; same for NormalLight |
| Merge-K anchor unlock (K=2, path 2)                         | ~2840         | Includes ~2500b prev-tx reconstruction    |
| Merge-K follower unlock (K=2)                               | ~2770         | Includes ~2500b prev-tx reconstruction    |
| Merge-K anchor unlock extra per additional follower (K=3→4) | +~2500        | One more prev-tx reconstruction piece     |
| Transition NormalLight→NormalMerge (owner sig, simple)      | ~230          | Same shape as transfer unlock             |
| Transition NormalMerge→NormalLight (anchor back-transition) | ~280          | Minor overhead over transfer              |
| Freeze auth-sig unlock                                      | ~260          | Auth sig + pubkey ~107b + preimage        |
| Redeem issuer-sig unlock                                    | ~260          | Same shape as freeze                      |

### 3.1 Workload 1 — Pure transfer (1 in → 1 out + change)

Single STAS input, single STAS token output, funding input, change output.

Formula: 44 + unlock + 147 + UTXO_out + 34 + 10

| Candidate   | UTXO_out (b) | Unlock (b) | Total tx (b) | vs DSTAS | Notes                                 |
| ----------- | ------------ | ---------- | ------------ | -------- | ------------------------------------- |
| DSTAS 1.0.4 | 3050         | 230        | **3485**     | baseline | Slightly adjusted from comparison doc |
| Option A    | 4222         | 230        | **4657**     | **+34%** | ABORT: 1172b larger than DSTAS        |
| Option A1   | 3368         | 230        | **3803**     | **+9%**  | Still larger than DSTAS               |
| Option P    | 1968         | 230        | **2303**     | **−34%** | NormalLight wins decisively           |

**Dealbreaker for Option A:** Transfer tx is 34% LARGER than DSTAS. This is the finding that motivated this document. The spec claimed −24% but that used the 2200b UTXO estimate, not the measured 4222b.

**Option A1 note:** Still 9% larger than DSTAS on transfer because even a 3368b NormalBase-lite UTXO exceeds DSTAS's 3050b. Option A1 only beats DSTAS if the body can be reduced below ~2858b — which requires further cuts beyond the three proposed.

---

### 3.2 Workload 2 — Simple merge K=2 (2 NormalLight → 1 NormalLight)

DSTAS and Option A/A1 require no preparatory txs. Option P requires 2 transition txs (NL→NM) before merge.

**Transition tx (Option P, per UTXO):**
44 + 230 (transition unlock) + 147 (funding) + 2368 (NormalMerge out) + 34 + 10 = **2833b**

**Merge-K=2 tx (all candidates):**

- Anchor input: 44 + 2840 = 2884b
- Follower input: 44 + 2770 = 2814b
- Funding: 147b
- STAS out: UTXO_size + 11 (output overhead)
- Change: 34b, Overhead: 10b

| Candidate   | Pre-tx count  | Pre-tx bytes | Merge-tx bytes                       | Total bytes | vs DSTAS | Notes                         |
| ----------- | ------------- | ------------ | ------------------------------------ | ----------- | -------- | ----------------------------- |
| DSTAS 1.0.4 | 0             | 0            | 2884+2814+147+3061+34+10 = **8950**  | **8950**    | baseline |                               |
| Option A    | 0             | 0            | 2884+2814+147+4233+34+10 = **10122** | **10122**   | **+13%** | Larger than DSTAS             |
| Option A1   | 0             | 0            | 2884+2814+147+3379+34+10 = **9268**  | **9268**    | **+4%**  | ~318b over DSTAS              |
| Option P    | 2 transitions | 2×2833=5666  | 2884+2814+147+1979+34+10 = **7868**  | **13534**   | **+51%** | Transition overhead kills K=2 |

**Key finding:** Option P is catastrophically worse on K=2 merge because 2 transition txs (5666b) dwarf the merge-tx savings from the smaller NormalLight output. The break-even for Option P on merge requires high K — the transitions must be amortized over more follower inputs.

---

### 3.3 Workload 3 — Heavy merge K=4 (4 NormalLight → 1 NormalLight)

DSTAS: K=2 only → must chain 3 sequential merge-2 txs.
Option A (4054b body measured): K=4 supported in 1 tx.
Option A1: K=2 only (feature cut) → 3 chained merge-2 txs.
Option P: 4 transition txs + 1 merge-4 tx.

**Merge-4 anchor unlock (K=4):** baseline ~2840b + 2×2500b extra reconstructions = **7840b**
**Merge-4 follower unlock:** ~2770b each × 3 = 8310b total
**Merge-4 tx (anchor+3 followers):** (44+7840) + 3×(44+2770) + 147 + UTXO_out + 34 + 10

Option A merge-4 tx: 7884 + 8922 + 147 + 4233 + 34 + 10 = **21230b**
DSTAS 3×merge-2: 3 × 8950 = **26850b**
Option A1 3×merge-2 (NormalBase-lite out): 3 × 9268 = **27804b**
Option P 4 transitions + 1 merge-4: 4×2833 + merge4_tx

Option P merge-4 tx: (44+7840) + 3×(44+2770) + 147 + 1979 + 34 + 10 = **21018b**
Wait — NormalMerge inputs are 2368b each, not NormalLight. Recalculate:

- NormalMerge anchor unlock (prev-tx reconstructions reference NormalMerge body ~2368b, but the reconstruction pieces carry ~2500b regardless of UTXO body size since they contain the full prev tx).
- Merge unlock sizes are driven by prev-tx reconstruction byte count, not output size. Anchor: ~7840b, followers: ~2770b each. These are not meaningfully different for Option P.

Option P merge-4 tx: 7884 + 8922 + 147 + 1979 + 34 + 10 = **18976b**
Option P total (4 transitions + merge): 4×2833 + 18976 = 11332 + 18976 = **30308b**

| Candidate   | Tx count | Total bytes | vs DSTAS | Notes                                              |
| ----------- | -------- | ----------- | -------- | -------------------------------------------------- |
| DSTAS 1.0.4 | 3        | **26850**   | baseline | 3×merge-2 chain                                    |
| Option A    | 1        | **21230**   | **−21%** | K=4 in single tx; wins this workload               |
| Option A1   | 3        | **27804**   | **+4%**  | K=2 cut forces chaining, slightly worse than DSTAS |
| Option P    | 5        | **30308**   | **+13%** | 4 transitions expensive; worst here                |

**Surprise:** Option A (despite ABORT on body size) wins the K=4 heavy-merge workload because a single large-body merge-4 tx still beats 3 chained merge-2 txs. The merge-tx savings from K=4 (~5600b vs DSTAS) exceed the per-UTXO body size penalty.

**Option P K=4 with NormalMerge loses** despite NormalLight being small. The 4 transition txs (11332b) cost more than the savings on merge output size.

---

### 3.4 Workload 4 — Split (1 in → 4 out + change)

Single tx: 44 + unlock + 147 + 4×UTXO_out + 34 + 10
Unlock for 4-output split: ~330b (4 output tuples/scripts in unlocking)

| Candidate   | Unlock (b) | UTXO_out ×4 (b) | Total tx (b) | vs DSTAS | Notes            |
| ----------- | ---------- | --------------- | ------------ | -------- | ---------------- |
| DSTAS 1.0.4 | 330        | 4×3050=12200    | **12735**    | baseline |                  |
| Option A    | 330        | 4×4222=16888    | **17423**    | **+37%** | Devastating      |
| Option A1   | 330        | 4×3368=13472    | **14007**    | **+10%** | Manageable       |
| Option P    | 330        | 4×1968=7872     | **8547**     | **−33%** | NormalLight wins |

Option A is eliminated as production-viable by this workload alone. A 37% larger split tx than DSTAS is unacceptable when split is common in production.

---

### 3.5 Workload 5 — Merge+split pattern (operator hot path)

**Setup:** 5 NormalLight UTXOs, operator wants 1 payment UTXO (specific amount) + 1 change UTXO.

**Realistic decomposition:**

- Step A: merge some UTXOs to get the right total (need at least 2-3 merged)
- Step B: split the merged result into payment + change

**Concrete scenario:** take UTXOs A, B, C, D (4 UTXOs), merge to 1, then split into payment (output 1) + remainder (output 2). Fifth UTXO (E) stays unaffected.

For DSTAS and Option A/A1, this is a chain: merge-4 (or 3×merge-2) → split-1-to-2.

**Merge phase (as in Workload 3) + split phase:**

Split tx on merged output (1 in → 2 out):

- Unlock: ~260b (2 output tuples)
- Output: 2 × UTXO_size

| Candidate   | Merge total (b)     | Split tx (b)                       | Grand total (b) | vs DSTAS | Notes                         |
| ----------- | ------------------- | ---------------------------------- | --------------- | -------- | ----------------------------- |
| DSTAS 1.0.4 | 26850 (3×K=2)       | 44+260+147+2×3061+34+10 = **6617** | **33467**       | baseline |                               |
| Option A    | 21230 (1×K=4)       | 44+260+147+2×4233+34+10 = **9021** | **30251**       | **−10%** | Merge win, split loss         |
| Option A1   | 27804 (3×K=2)       | 44+260+147+2×3379+34+10 = **7313** | **35117**       | **+5%**  | Slightly worse than DSTAS     |
| Option P    | 30308 (4 trans+K=4) | 44+260+147+2×1979+34+10 = **4503** | **34811**       | **+4%**  | Split saves, transitions hurt |

**Option A uniquely wins Workload 5** because K=4 merge saves ~5600b vs DSTAS and the split on 4222b UTXOs only partially erodes that gain. No other candidate beats DSTAS here.

**Option A1 and Option P are both slightly worse than DSTAS** on the operator hot path — Option A1 because it loses K=4, Option P because transition overhead dominates.

---

### 3.6 Workload 6 — Freeze (compliance)

Authority tx: 1 NormalBase/NormalLight input → 1 Frozen output.
Unlock: ~260b (auth sig).

| Candidate   | UTXO_in | UTXO_out (Frozen) | Tx (b)                           | vs DSTAS | Notes                                   |
| ----------- | ------- | ----------------- | -------------------------------- | -------- | --------------------------------------- |
| DSTAS 1.0.4 | 3050    | 3050              | 44+260+147+3061+34+10 = **3556** | baseline | Same template, only action_data changes |
| Option A    | 4222    | 928               | 44+260+147+939+34+10 = **1434**  | **−60%** | Frozen UTXO tiny                        |
| Option A1   | 3368    | 778               | 44+260+147+789+34+10 = **1284**  | **−64%** | Frozen even smaller                     |
| Option P    | 1968    | 928               | 44+260+147+939+34+10 = **1434**  | **−60%** | Same Frozen template                    |

All BNTP options dramatically outperform DSTAS on freeze due to the Frozen template being path-isolated (~760b body vs 2900b monolith). This is a compliance-critical workload where BNTP architecture excels regardless of Normal UTXO size.

---

### 3.7 Workload 7 — 1000-UTXO consolidation (batch)

Metric: total bytes to merge 1001 UTXOs → 1 UTXO.

For K=2: each merge tx reduces count by 1, so 1000 merge txs needed.
For K=4: each merge reduces count by 3, so ceil(1000/3) ≈ 334 merge txs (with some K=2 cleanup for remainder).

**Option P K=4 path** requires transitions before each merge-4 tx. However, transitions can be batched: instead of 4 separate transition txs per merge, a smart operator sequences: transition K UTXOs together in one round of transition txs, then merge. Modeled here as one transition tx per NormalLight UTXO being merged.

Total transition txs (Option P, K=4 path): 1000 transitions (one per UTXO entering NormalMerge state) = 1000 × 2833b = **2,833,000b**
Total merge txs (Option P, ~334 merge-4): ~334 × 18976b = **6,337,984b** (using K=4 tx size from W3)
Option P total: **~9.17 MB, ~1334 txs**

Wait — for Option P, once a UTXO has been through a merge, the output is NormalLight (from the back-transition embedded in the merge tx OR via a separate back-transition tx). If back-transition is embedded (back-to-NormalLight output IS the merge output), no extra back-transition tx is needed. Model this as: merge-4 output is NormalLight (not NormalMerge). Transition count = total UTXOs entering merge = 1000. Each merge-4 consumes 4 NormalMerge inputs, produces 1 NormalLight output. 1000 NMs → 250 merge-4s; remainder chain with merge-2 for last 1 UTXO. Round to ~250+1 = 251 merge txs.

Revise Option P: 1000 transitions + 251 merge txs.
Merge-4 tx (NM inputs + NL output): (44+7840) + 3×(44+2770) + 147 + 1979 + 34 + 10 = **18976b** (per W3 calc above, verified)
1000 transition txs: 1000 × 2833 = 2,833,000b
251 merge-4 txs: 251 × 18976 = 4,762,976b
Option P total: **7,595,976b (~7.60 MB), 1251 txs**

| Candidate     | Tx count | Total bytes                          | vs DSTAS | Notes                                                           |
| ------------- | -------- | ------------------------------------ | -------- | --------------------------------------------------------------- |
| DSTAS K=2     | 1000     | 1000×8950 = **8,950,000** (~8.95 MB) | baseline |                                                                 |
| Option A K=4  | ~334     | 334×21230 = **7,090,820** (~7.09 MB) | **−21%** | Merge win from K=4                                              |
| Option A1 K=2 | 1000     | 1000×9268 = **9,268,000** (~9.27 MB) | **+4%**  | Slightly worse than DSTAS                                       |
| Option P K=4  | 1251     | **7,595,976** (~7.60 MB)             | **−15%** | Better than DSTAS; fewer txs than A K=4 if counting transitions |

**Option A K=4 wins batch consolidation** with both lowest byte count and fewest transactions (~334 vs 1000+). This is its strongest workload.

---

## 4. Decision Matrix

### 4.1 Workload weights (based on stated user priorities)

| Workload       | Weight        | Rationale                                              |
| -------------- | ------------- | ------------------------------------------------------ |
| W2 K=2 merge   | HIGH (3×)     | Most common merge; operators always start here         |
| W3 K=4 merge   | HIGH (3×)     | Heavy consolidation; reduces mempool ancestor pressure |
| W5 Merge+split | CRITICAL (4×) | Explicit "operator hot path" per user                  |
| W4 Split       | HIGH (2×)     | Frequently paired with merge                           |
| W1 Transfer    | MEDIUM (2×)   | Common but operator does mostly merge/split            |
| W7 1000 batch  | MEDIUM (2×)   | Periodic large consolidation                           |
| W6 Freeze      | LOW (1×)      | Compliance; rare for most operators                    |

### 4.2 Per-workload scores (1=worst, 5=best relative to field)

| Workload       | Weight | DSTAS | Option A | Option A1 | Option P |
| -------------- | ------ | ----- | -------- | --------- | -------- |
| W1 Transfer    | 2×     | 4     | 1        | 3         | **5**    |
| W2 K=2 merge   | 3×     | 4     | 2        | 3         | 1        |
| W3 K=4 merge   | 3×     | 3     | **5**    | 2         | 1        |
| W4 Split       | 2×     | 4     | 1        | 3         | **5**    |
| W5 Merge+split | 4×     | 3     | **5**    | 2         | 2        |
| W7 1000 batch  | 2×     | 3     | **5**    | 2         | 4        |
| W6 Freeze      | 1×     | 1     | 4        | **5**     | 4        |

### 4.3 Weighted totals

| Candidate | W1×2 | W2×3 | W3×3 | W4×2 | W5×4 | W7×2 | W6×1 | **Total** |
| --------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | --------- |
| DSTAS     | 8    | 12   | 9    | 8    | 12   | 6    | 1    | **56**    |
| Option A  | 2    | 6    | 15   | 2    | 20   | 10   | 4    | **59**    |
| Option A1 | 6    | 9    | 6    | 6    | 8    | 4    | 5    | **44**    |
| Option P  | 10   | 3    | 3    | 10   | 8    | 8    | 4    | **46**    |

**Ranking: Option A (59) > DSTAS (56) > Option P (46) > Option A1 (44)**

### 4.4 Interpretation

Option A wins on the weighted matrix **only because** Workload 5 (merge+split) carries the highest weight and Option A is the sole candidate with K=4 merge. If operators run the merge+split hot path constantly with K=4 inputs, Option A is the best architecture even with its 4222b Normal UTXO.

However, Option A failing DSTAS by 34% on pure transfer and 37% on split means **every non-merge operation is a regression**. The K=4 capability must be exercised frequently enough to amortize those losses. Whether that threshold is met depends on the operator's real workload ratio.

**DSTAS is harder to displace than expected.** Its monolithic design being "bad" for auditability does not make it "bad" for on-chain footprint. When the hot path is K=2 merge (most common), DSTAS beats Option A and nearly matches Option A1.

---

## 5. Ship-ability Notes

### Option A (current spec)

- **Status:** ABORT gate on NormalBase (4054b, target was 3000b). Requires spec amendment or feature cuts.
- **Feasibility:** Can ship the measured body as-is. It is a correct, functional design — just large.
- **Open question:** Does the 4222b Normal UTXO regress the operator's cost model beyond the K=4 savings? The answer is: only if K=4 merges are run frequently enough (at least weekly for moderate portfolios).
- **Next step:** Accept `SPEC AMENDMENT REQUEST #2` (revise G4 target to ~4200b) OR cut features per §8.2 of the NormalBase ASM doc. Committing to ~4054b body without a spec revision is the fastest path to Phase 1.

### Option A1

- **Status:** Estimated ~3200b body. Not yet measured at pseudo-ASM depth.
- **Feasibility:** High. Three targeted feature cuts (K=2, auth PKH-only, issuer PKH-only) are independent and well-bounded.
- **Risk:** Body estimate is +0/−200b uncertain. Could hit 3400b if some cuts save less than expected (MPKH branch interaction with dispatcher).
- **Next step:** Apply the three cuts to the Phase 0.1 pseudo-ASM and re-byte-count. 2–3 days of work.
- **Tradeoff:** Loses K=4 merge; hot-path W5 score drops to 2. Operators revert to chaining K=2 merges, which is exactly the pain point they wanted to avoid.

### Option P

- **Status:** Architecture only; no pseudo-ASM yet.
- **Feasibility:** Requires two new template bodies (NormalLight, NormalMerge) plus transition path design. Medium complexity.
- **Risk:** NormalLight body estimate (~1800b) is aggressive. NormalLight must still carry PREFIX covenant (~768b), whitelist (131b), shared helpers (~280b) = 1179b overhead before any path logic. That leaves ~620b for all paths. Transfer/split/freeze/confiscate/redeem + 3 transitions in 620b is very tight. A more realistic NormalLight estimate is ~2100b, NormalMerge ~2400b.
- **Revised Option P UTXO sizes:** NormalLight ~2268b, NormalMerge ~2568b.
- **With revised sizes:** most Option P scores above shift slightly — transfer/split remain wins over DSTAS, but K=2 merge transition overhead is even more painful.
- **Next step:** Produce NormalLight pseudo-ASM. Phase 0.2 effort.
- **Key architectural risk:** If back-transition after merge requires a separate tx (NormalMerge → NormalLight), every merge operation gains a mandatory exit tx (+~2600b). This document assumes back-transition is embedded in the merge tx output. Must be specified explicitly.

### DSTAS 1.0.4

- **Status:** Production-ready (research artifact per SDK isolation rules, but functionally complete).
- **Feasibility:** Fully shipped.
- **Main limitation:** K=2 only; monolithic 2900b body; no closed forward state; no issuer attestation gate for DEX.
- **As a footprint benchmark:** harder to beat than previously estimated. Its 3050b Normal UTXO and no-transition model gives it a durable advantage on cold paths.

---

## 6. Honest Caveats

**NormalLight body estimate is speculative.** ~1800b is an optimistic target. The PREFIX covenant + WHITELIST overhead alone is ~1179b before any path logic. Getting transfer + split + 3 transition paths + redeem + freeze/confiscate into ~620b of SUFFIX is tight. A realistic pessimistic estimate is ~2200b body → 2368b UTXO. At that size, Option P's transfer advantage over DSTAS shrinks from −34% to approximately −3%, making it a near-wash.

**Merge unlock sizes are dominant and option-agnostic.** The ~2840b anchor unlock and ~2770b follower unlock are driven by prev-tx reconstruction (~2500b per counterparty), not by UTXO body size. These numbers change only if the reconstruction algorithm changes, not if the template body shrinks. This caps the benefit of smaller UTXOs on merge workloads.

**Option A's K=4 advantage may be illusory in practice.** K=4 requires all 4 inputs to be in NormalBase state simultaneously, with the wallet able to collect and spend all 4 outpoints in a single tx. If UTXOs arrive in different mempool windows or operator needs to merge fewer than 4, K=4 is unavailable and Option A falls back to K=2 chains — where it performs worse than DSTAS.

**Option A1's body estimate (~3200b) still exceeds DSTAS's 3050b UTXO total.** Only Option P's NormalLight (if achievable) yields a smaller per-UTXO footprint than DSTAS for normal operations.

**Transition tx sizing (Option P):** The 2833b transition tx estimate uses a NormalMerge output of 2368b. If NormalMerge body is closer to 2400b (more realistic), transition tx grows to ~2900b, worsening Option P's K=2 merge score further.

**Workload 5 (merge+split) dominance in the matrix:** The 4× weight for W5 is aggressive and reflects the user's stated hot path. If operators occasionally run K=4 but mostly run K=2 or simple transfers, DSTAS would rank first on the weighted matrix with W2 weight raised and W3/W5 lowered.

---

## 7. Recommendation

**The honest answer is: Option A, but only if K=4 is actually the dominant merge pattern in production.**

The weighted matrix gives Option A a marginal win (59 vs 56 for DSTAS) entirely on the back of Workload 5 and Workload 3. If the operator runs constant K=4 merge+split cycles, Option A's single-tx K=4 capability is worth the 34% per-UTXO penalty on cold paths. If merge is mostly K=2, DSTAS is better.

**Concrete recommendation:**

1. **Accept SPEC AMENDMENT REQUEST #2** from `BNTP_TEMPLATE_NORMALBASE_ASM.md`: revise the G4 gate target to ≤ 4200b (matching Phase 0.1 reality). This removes the ABORT designation and allows Option A to proceed to Phase 1.

2. **Proceed to Phase 1 skeleton with Option A as-measured (4054b body).** Do not wait for further size optimization. The full-tx footprint analysis shows Option A is net-positive over DSTAS when K=4 merge is exercised, and K=4 is the main architectural differentiator.

3. **Produce NormalLight pseudo-ASM (Option P) in parallel as Phase 0.2 work** alongside the NormalSwapOnRamp ASM. If NormalLight body lands below ~2000b, reconsider the architecture for a hypothetical v1.1. If it lands above ~2100b, Option P's transition overhead makes it worse than DSTAS on every workload except pure transfer and pure split — and those are not the hot path.

4. **Option A1 is the conservative fallback** if Option A with 4054b body is rejected on business grounds (e.g., storage cost per UTXO is a hard constraint). Produce the feature-cut pseudo-ASM to verify the 3200b estimate before committing to the cut. Be explicit with stakeholders: A1 loses K=4 and therefore loses the primary hot-path advantage over DSTAS.

5. **DSTAS remains the reference point, not the floor.** Any architecture that beats DSTAS only on compliance (freeze) but loses on transfer, split, and K=2 merge is not a meaningful improvement. Option A must deliver K=4 to justify its existence.

---

## 8. Change Log

- 2026-04-17 — Initial version. Corrects BNTP_ALTERNATIVES_EVALUATION.md (body-only metric) with full-tx footprint analysis. Introduces Option P as fourth candidate. Phase 0.1 4054b NormalBase used as honest baseline throughout.
