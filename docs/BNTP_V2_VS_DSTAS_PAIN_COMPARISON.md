# BNTP v2 vs DSTAS 1.0.4 — Pain Resolution Analysis

**Status:** Research deliverable. Not a spec. Companion to `BNTP_FULL_TX_FOOTPRINT_COMPARISON.md` (v1 vs DSTAS, footprint-focused).
**Date:** 2026-04-17
**Scope:** Pain-resolution metrics only. Footprint appears as a secondary reference, not the primary lens.

---

## 1. Executive Summary

DSTAS 1.0.4 has two structural pains that make it difficult to adopt at scale: (1) merge pain — the satoshis-as-amount design forces a "merge then transfer" workflow for most real-world payments, multiplying transaction counts and costs; and (2) back-to-genesis (B2G) verification cost — wallets cannot cheaply verify UTXO legitimacy without walking a potentially deep chain back to the genesis transaction.

BNTP v2 attacks both pains at the architectural root. Amount-in-tail (uint128) eliminates the merge/transfer distinction entirely: a single `flex-transfer` handles N-to-M arbitrary redistribution with on-script conservation, cutting a 2-3 tx workflow to 1 tx. B2G verification shifts from O(depth) chain walk to O(1) issuer-attestation check for fresh UTXOs (depth=0), using a rolling depth counter and an explicit refresh path.

The cost of these wins is real: BNTP v2 introduces issuer liveness dependency, a royalty on the refresh path, and a trust model shift from "verify the chain" to "trust the issuer's attestation." These trade-offs are acceptable for regulated or high-value tokens where the issuer is already a trusted counterparty. They are more contentious for utility tokens where trustless operation matters.

On the primary pain metrics, BNTP v2 substantially dominates DSTAS. On adoption friction, it introduces new dependencies that DSTAS does not have. The net picture: a clear improvement for the target pain profile, with honest trade-offs that need to be acknowledged upfront.

---

## 2. Pain Resolution Matrix

Scoring: 1 = no improvement or regression; 2 = marginal; 3 = partial; 4 = mostly resolved; 5 = fully eliminated.

| Pain                      | DSTAS 1.0.4 | BNTP v2 | Delta | Notes                                                                                  |
| ------------------------- | ----------- | ------- | ----- | -------------------------------------------------------------------------------------- |
| **Merge pain**            | 1           | 5       | +4    | Fully eliminated by amount-in-tail + flex-transfer                                     |
| **B2G verification cost** | 1           | 4       | +3    | O(1) for fresh UTXOs; residual for stale (depth > threshold)                           |
| **DEX readiness**         | 2           | 3       | +1    | B2G-solved UTXOs are DEX-ready; stale UTXOs need refresh first                         |
| **Compliance readiness**  | 3           | 4       | +1    | Frozen template 76% smaller; MPKH authority paths add enterprise value                 |
| **Wallet UX**             | 2           | 4       | +2    | Single flex-transfer replaces multi-step prepare+pay; freshness policy adds complexity |
| **Adoption friction**     | 3           | 2       | -1    | BNTP v2 adds issuer liveness dependency and royalty on refresh; DSTAS has none         |
| **Footprint** (secondary) | 3           | 4       | +1    | Normal UTXO ~30% smaller; merge tx ~74-90% smaller; Frozen ~76% smaller                |

### Weighted score

Weights reflect pain priority: merge pain (4), B2G cost (4), DEX readiness (2), compliance (1.5), wallet UX (2), adoption friction (1.5), footprint (0.5).

| Candidate   | Merge×4 | B2G×4 | DEX×2 | Compliance×1.5 | Wallet×2 | Friction×1.5 | Footprint×0.5 | **Total** |
| ----------- | ------- | ----- | ----- | -------------- | -------- | ------------ | ------------- | --------- |
| DSTAS 1.0.4 | 4       | 4     | 4     | 4.5            | 4        | 4.5          | 1.5           | **26.5**  |
| BNTP v2     | 20      | 16    | 6     | 6              | 8        | 3            | 2             | **61**    |

**BNTP v2 weighted score: 61. DSTAS weighted score: 26.5.**

The gap is driven almost entirely by the two primary pains (merge + B2G), where BNTP v2 scores near-maximum and DSTAS scores minimum. The regression on adoption friction (DSTAS 3 → BNTP v2 2, weighted 1.5) does not offset this.

---

## 3. Per-Workload Analysis (W1-W7)

### W1: Pay X to Alice from mixed UTXOs

**Scenario:** Wallet has UTXOs of 50, 80, 120 tokens. Needs to pay Alice exactly 100.

**DSTAS behavior:**
Since token amount equals satoshis, paying 100 from 80+120 requires: (a) merge tx: 80+120=200 merged UTXO (~9800b); (b) transfer/split tx: 200→100 payment + 100 change (~3471b). Total: 2 txs, ~13.3 KB. Alternatively, merge 50+80=130, then split: same structure. No single-tx path exists.

**BNTP v2 behavior:**
flex-transfer with 2 inputs (80+120 or 50+80): 1 tx, ~2.5-2.6 KB. Amount-in-tail means the script only needs `Σ inputs == Σ outputs` — no dependency on satoshi values. Output 0 = 100 to Alice (depth = max(input depths)+1). Output 1 = 20 or 30 change. The prepare+pay workflow is gone.

**Winner:** BNTP v2, by 2x fewer txs and ~80% fewer bytes.

**Trade-offs:** None of substance for this workload. The only difference is that BNTP v2's output depth increments on every transfer, which eventually requires a refresh. For infrequent payments this is invisible.

---

### W2: Heavy consolidation — 10 UTXOs to 1

**DSTAS behavior:**
DSTAS is K=2 only (merge two inputs at a time). Consolidating 10 UTXOs requires 9 chained merge-2 txs. Each merge-2 tx: ~9800b (anchor unlock ~2840b + follower ~2770b + input overheads + output UTXO ~3050b + misc). Total: 9 × ~9800b = ~88 KB, 9 txs. The anchor/follower pattern requires each input to carry a full prev-tx reconstruction (~2500b), making each merge dominated by unlocking size regardless of UTXO body.

**BNTP v2 behavior:**
flex-transfer supports N inputs where N ≥ 1. Reasonable practical limit based on unlocking size is N ≈ 8 (amounts_array grows at 16b/input, outpoints at 36b/input — 8-input unlocking ~580b). For 10 UTXOs: 1 flex-transfer with 8 inputs → 1 output, followed by 1 flex-transfer with 2 remaining + previous output → 1 final output. Total: 2 txs. Alternatively, if script limit is N ≤ 10 (nothing in spec prevents it), 1 tx.

Estimated: 2 txs, ~6-8 KB total (no prev-tx reconstruction; amounts_array + outpoints_array scale linearly at ~52b/input).

**Winner:** BNTP v2. 2 txs vs 9 txs; ~88 KB vs ~7 KB. Ratio: ~91% byte reduction.

**Trade-offs:** Output depth after consolidation = max(all input depths) + 1, which may trigger a refresh need if depths were already high. This is intentional — the consolidation itself is cheap; refreshing thereafter if needed is a separate economic decision.

---

### W3: Receive token from unknown sender — B2G verification

**Scenario:** Wallet receives a UTXO from a counterparty. Needs to verify the token is legitimate before accepting.

**DSTAS behavior:**
The locking script carries no provenance proof. A forged UTXO with identical `redemptionPkh` and script body is indistinguishable from a genuine one at the script level (confirmed in `DSTAS_LOCKING_SCRIPT_AUDIT.md` §2.1). Wallet must walk the chain backward to the genesis transaction, verifying each intermediate spending-type-1 (transfer/merge) is valid. For a token with 500 transfers in history: 500 network calls to retrieve transactions, 500 hash verifications, plus parsing each tx for script structure. Time: seconds to minutes depending on indexer. Developer complexity: high (custom chain-walk logic with exception handling).

**BNTP v2 behavior:**
On receiving a UTXO, wallet checks: (1) `issuerPkh` present in trusted issuer registry — O(1) lookup; (2) `attestation_depth` is below wallet policy threshold (e.g., depth ≤ 50). If both conditions met, token is accepted without chain walk. The depth counter is tamper-resistant: script enforces `new_depth ≥ max(input depths) + 1` on every flex-transfer and `depth = 0` only on refresh or confiscate. An attacker cannot forge a depth=0 UTXO without a valid issuer attestation in that tx.

For stale UTXOs (depth > threshold), wallet can: warn the user, request the sender to refresh first, or perform a bounded chain walk from last depth=0 anchor (much shorter than full walk to genesis).

**Winner:** BNTP v2 for fresh UTXOs (O(1) vs O(depth) network operations). Marginal advantage for deeply stale UTXOs (bounded walk from last anchor vs unbounded walk to genesis).

**Trade-offs:** The "trust issuer" check shifts trust from the chain to the issuer. If the issuer's registry is wrong or the issuer is compromised, wallets will accept bad tokens. This is a trust model change, not a purely technical improvement. However, for tokens where an issuer is already a trusted legal entity (securities, stablecoins), this is an acceptable or even preferred trust model.

---

### W4: Send token to DEX for swap

**DSTAS behavior:**
User can send a UTXO directly to the DEX without additional preparation. However, the DEX itself must verify B2G on every incoming UTXO before listing or executing a swap. This shifts cost to the DEX, but the DEX-side verification is the same expensive chain walk. The DEX's own B2G cost is significant infrastructure (indexed chain walk, dedicated verification service). From the user's perspective: 0 additional steps before sending. From the ecosystem's perspective: B2G cost is paid by the DEX, not the user.

**BNTP v2 behavior:**
If the UTXO is fresh (depth within DEX's policy threshold), the DEX can verify in O(1) and the UTXO is immediately listable. If stale (depth > threshold), user must run a refresh tx first (+1 tx, royalty cost, requires issuer online). After refresh, UTXO is depth=0 and DEX accepts it. Net user steps for fresh UTXOs: 0 extra. For stale UTXOs: 1 extra (refresh), plus royalty cost.

**Winner:** BNTP v2 slightly for fresh UTXOs (DEX complexity dramatically lower = better ecosystem liquidity). Tie or DSTAS wins for stale UTXOs where refresh is needed. The refresh requirement introduces friction that DSTAS doesn't have.

**Trade-offs:** DEX integration is simpler with BNTP v2 (lower verification cost) but requires the DEX to set and communicate a depth threshold policy. Users with old UTXOs face refresh cost. If refresh is expensive (high royalty or issuer slow), this is a real barrier to DEX participation.

---

### W5: Periodic refresh (BNTP v2 specific)

**DSTAS behavior:** N/A. No refresh concept exists.

**BNTP v2 behavior:**
Refresh tx: 1 BNTP input → 2 BNTP outputs (user's refreshed UTXO + issuer's royalty). Both outputs get depth=0. The issuer's attestation is in a null-data output (~110b). Total refresh tx: ~2900b. Royalty: issuer policy, protocol floor of 1 token unit. The spec notes issuer may scale royalty with depth (higher depth = more off-chain chain-walk cost for issuer to verify before signing). This means high-depth UTXOs cost more to refresh, which naturally discourages neglect.

**Critical question for pain resolution:** Is the refresh mechanism cheap enough to not turn "B2G solved" into "B2G deferred to refresh cost"?

Analysis: For a token with issuer charging 1% royalty, refreshing a 1000-unit UTXO costs 10 units. If the token is used 50 times between refreshes, the amortized cost is 0.2 units/transfer. This is comparable to BSV transaction fees at current rates and acceptable for regulated tokens. For very high-frequency low-value tokens, 1% per refresh on every batch could be significant.

**Score for W5:** Viable as a mechanism. Not a blocker if issuer pricing is reasonable. Becomes a pain if issuer is predatory or if refresh frequency is forced to be high.

---

### W6: Cross-token swap — Alice has token A, wants token B

**DSTAS behavior:**
DSTAS has a built-in swap path (spending_type=4). The on-chain swap protocol uses the `requestedScriptHash` and `requestedPkh` in the action_data to specify the counterparty token. Swap execution is a 2-input tx where each input verifies the other's prev-tx. Unlocking for each input carries the counterparty's full prev-tx (~2500b reconstruction). Total tx: ~19 KB for a 2-input swap. B2G vulnerability applies: nothing prevents a forged counterparty UTXO passing script verification.

**BNTP v2 behavior:**
Swaps are explicitly out-of-protocol. An external swap protocol (DEX, P2P atomic swap) builds a tx with 2 BNTP Normal UTXOs (one per token) as inputs. Each input's script runs its own `flex-transfer` verification independently: token A input verifies conservation of token A, token B input verifies conservation of token B. Atomicity is guaranteed by the fact that both inputs must be signed in the same tx (standard Bitcoin atomic semantics). No cross-input communication needed in the script; each input is self-contained.

Estimated tx size for 2-token atomic swap: 2 flex-transfer unlockings (~260b each) + 2 Normal UTXO inputs + 2 Normal UTXO outputs + overhead = ~2 × (44 + 260) + 2 × 2133 + overhead ≈ 4900b. This is approximately 75% smaller than the DSTAS equivalent (~19 KB) because DSTAS swap carries prev-tx reconstruction.

**Winner:** BNTP v2. Simpler protocol, smaller tx, no B2G vulnerability in counterparty verification. However, the external protocol layer must be specified and implemented separately — this is design work that BNTP v2 intentionally defers.

**Trade-offs:** DSTAS swap is a built-in primitive; the UX is integrated in the SDK. BNTP v2's swap requires a separate external protocol to be built, agreed upon, and deployed. Until that protocol exists, cross-token swaps require more infrastructure investment.

---

### W7: Compliance freeze event

**Scenario:** Freeze authority freezes a suspicious UTXO.

**DSTAS behavior:**
Freeze is spending_type=2. The Frozen UTXO uses the same ~3050b template as Normal (only action_data byte changes). Freeze tx: ~3570b (includes 3050b Frozen output). Frozen UTXOs live on-chain potentially for years, each costing full template size for as long as they exist. For a compliance-heavy token with 500 frozen UTXOs, that's 500 × 3050b = ~1.5 MB of frozen-state storage.

**BNTP v2 behavior:**
Frozen template is path-isolated and small (~600b body, ~733b total UTXO vs ~3050b for DSTAS). Freeze tx: ~1150b (60% smaller than DSTAS). Long-term storage cost for 500 frozen UTXOs: 500 × 733b = ~367 KB vs ~1.5 MB. The authority unlock for freeze is also ~260b (same order as DSTAS).

**Winner:** BNTP v2. 68% smaller freeze tx, 76% smaller Frozen UTXOs for long-term storage. For compliance-heavy tokens with large freeze inventories, this compounds meaningfully.

**Trade-offs:** None of significance. This is a clean win.

---

## 4. Where BNTP v2 Wins

**1. Merge pain: fully eliminated (+4 score delta, largest gain)**
The satoshis-as-amount problem is solved at the architecture level, not patched. Any N-to-M redistribution is a single flex-transfer. The 2-3 tx merge+split workflow common in production becomes 1 tx. Unlocking size for 4-input consolidation: ~460b (v2) vs ~10,000b (DSTAS anchor+followers). This is the most impactful change.

**2. B2G verification: O(1) for fresh UTXOs (+3 score delta)**
Wallet verification of a fresh UTXO (depth=0) requires one registry lookup and one uint16 check. For DEXes, indexers, and casual wallets, this is a massive operational simplification. The depth counter is tamper-resistant: script-enforced monotonic increment means attackers cannot forge low depth without a valid issuer attestation.

**3. Frozen UTXO size (-76% per UTXO)**
For regulated tokens, this is a persistent cost saving. Frozen UTXOs often sit on-chain for months or years during legal proceedings. 76% reduction in per-UTXO size at steady state.

**4. Atomic swap size (-75%)**
An external 2-token swap built on BNTP v2 is approximately 4900b vs DSTAS's ~19 KB because BNTP v2 needs no prev-tx reconstruction. This makes DEX architecture more feasible on BSV.

**5. Normal UTXO footprint (-30%)**
Even on simple transfers, BNTP v2 Normal UTXO (~2133b) is 30% smaller than DSTAS (~3050b). Not the primary goal, but a consistent secondary benefit.

**6. MPKH authority and owner support**
BNTP v2 supports m-of-n multisig for owner, issuer, freeze authority, and confiscation authority via the MPKH flag bits. This enables enterprise treasury wallets and federated compliance authorities, which DSTAS's PKH-only design cannot support without external wrapping.

---

## 5. Where BNTP v2 Loses or Is Ambiguous

**1. Adoption friction: issuer liveness dependency (regression: -1 score)**
DSTAS has no issuer involvement after issuance. Transfers are purely owner-signed. In BNTP v2, the refresh path requires the issuer to be online, verify the chain from last anchor, and sign. If the issuer's service is down, offline, slow, or has raised prices, refresh is blocked. This creates a service dependency that DSTAS avoids entirely. For tokens where the issuer is a regulated entity (a bank, a securities issuer), this is acceptable — they are already a trusted counterparty. For decentralized utility tokens, it is a real regression.

**2. Trust model shift**
DSTAS's B2G weakness is at least honest: wallets know they must verify the chain themselves. BNTP v2's attestation model provides apparent simplicity (O(1) check) but moves the trust anchor to the issuer registry. If the registry is wrong, the issuer is compromised, or the issuer has colluded to attest a fraudulent UTXO, wallets have no on-chain fallback. This is acknowledged in the spec (§13.1) but deserves repeated emphasis: the B2G "solution" is not trustless. It is a trust model substitution: chain trust → issuer trust.

**3. Royalty cost on refresh**
Every refresh tx takes a royalty from the token's own amount. For long-lived tokens that are transferred frequently, the cumulative royalty drain is non-trivial. Example: 1% royalty, refreshed every 50 transfers, 100-unit UTXO → 1 unit royalty per refresh → token loses 1% of value per ~50-transfer cycle. Over the token's life this compounds. The spec acknowledges (§7.4) that royalty floor is 1 token unit (anti-dust) with no protocol ceiling, leaving predatory pricing possible.

**4. Depth threshold management creates UX complexity**
Wallets must implement and communicate a depth threshold policy. Users receive UTXOs of varying depths; wallets need policy logic for "accept at depth N", "warn at depth M", "require refresh at depth P". This is a new class of user-facing complexity that DSTAS has no equivalent of.

**5. External swap protocol is not yet specified**
BNTP v2 delegates cross-token swaps to an external protocol layer. This is architecturally clean but practically deferred. Until a swap protocol over BNTP v2 UTXOs is specified, reviewed, and deployed, cross-token swaps require more coordination work than with DSTAS's built-in swap path. DEX operators cannot build on BNTP v2 swaps until that work is done.

**6. Redeem path is simplified (possible compliance gap)**
BNTP v2 collapses the redeem path into a flex-transfer to issuer's address (§9.6 resolution in spec). If redeem has distinct legal semantics (e.g., "token destruction" vs "transfer to issuer") in a compliance context, this simplification may create a compliance gap that requires off-chain documentation or a future protocol amendment.

**7. Footprint win is real but modest on simple paths**
A simple 1→1 transfer: DSTAS ~3485b, BNTP v2 ~2350b (−32%). Useful, but not transformative. DSTAS's monolithic design is hard to beat on cold paths. BNTP v2's footprint advantage is decisive only on merge-heavy workloads.

---

## 6. Business Model Implications

BNTP v2 is not purely a protocol — it is also a service. The attestation/refresh model means the issuer must operate an ongoing signing service, not just a one-time mint contract.

**Revenue streams for issuer:**

- Royalty on each refresh tx (token-denominated, charged directly out of UTXO amount)
- Potential subscription fees for "guaranteed refresh within N hours" SLA
- Depth-scaled pricing: higher depth = more off-chain verification work = higher royalty (natural cost alignment)

**Incentive alignment:**
The issuer has a direct financial incentive to operate the attestation service reliably (revenue from royalties) and to keep depth thresholds reasonable (too-frequent forced refreshes could drive users to competitor tokens). This creates a market-based check on issuer behavior.

**Decentralization trade-offs:**
BNTP v2 is more centralized than DSTAS for ongoing operations. DSTAS issuers need only issue; BNTP v2 issuers need to operate a perpetual service. Using MPKH issuer (flag bit 4) with a federation of signers mitigates single-point-of-failure risk but adds operational complexity. The spec's reference to "subscription, batch signing, depth-scaled pricing" in §14 (Phase 4) indicates this infrastructure is real and non-trivial to build.

**Risk of issuer capture:**
If a BNTP v2 token becomes widely adopted, the issuer gains significant leverage over users via the refresh mechanism. An issuer that raises royalties, goes offline, or sells the signing key has tools to effectively tax or freeze the token ecosystem in ways DSTAS issuers do not. Governance mechanisms (DAO-based issuer rotation, MPKH with community threshold) would mitigate this but are not specified in BNTP v2.

---

## 7. Adoption Scenarios

### Tokens where BNTP v2 is clearly better

**Regulated financial tokens (securities, stablecoins, CBDCs):**
The issuer is already a regulated entity with legal obligations and infrastructure. Issuer liveness is a feature, not a bug — regulatory frameworks often require issuer involvement in transfers anyway. B2G verification via attestation fits naturally into existing compliance workflows. MPKH authority paths support institutional key management. Score: BNTP v2 strongly preferred.

**DEX-oriented tokens with high swap volume:**
The B2G cost at the DEX is a real infrastructure expense with DSTAS. BNTP v2's O(1) freshness check dramatically reduces DEX-side verification cost, making BSV token DEXes more economically viable. The external swap protocol overhead (to be built) is a one-time cost amortized over many swaps. Score: BNTP v2 preferred once swap protocol is specified.

**Compliance-heavy tokens with frequent freeze events:**
The 76% Frozen UTXO size reduction and smaller freeze tx size are persistent savings. For asset tokens with large compliance inventories, this matters. Score: BNTP v2 preferred.

**Low-frequency, high-value transfers:**
Refresh cost amortized over few transfers; issuer liveness less critical (infrequent contact); depth grows slowly. The B2G simplification benefits are high. Score: BNTP v2 preferred.

### Tokens where DSTAS may be better

**High-velocity utility payments (micropayments, in-app currency):**
Very frequent transfers → depth increases rapidly → frequent refreshes required → royalty cost could be significant fraction of value. If refresh royalty is 1% and users transfer many times daily, annual token drain becomes visible. Issuer liveness at scale (many simultaneous refresh requests) is also a challenge. Score: DSTAS may be better, depending on issuer pricing.

**Permissionless, issuer-free tokens:**
If the token design requires the issuer to be uninvolved post-issuance (e.g., algorithmic tokens, community governance tokens), BNTP v2's refresh requirement creates an irreconcilable dependency. Score: DSTAS preferred.

**Short-lived promotional tokens:**
Tokens with defined short lifespans (event tickets, coupons) may never reach problematic depths. The merge pain is minimal if few transfers happen. B2G is verifiable from a recent genesis. Score: DSTAS is simpler and sufficient.

---

## 8. Honest Caveats

**1. BNTP v2 body sizes are targets, not measured.**
The spec estimates Normal body at ~2000b and Frozen at ~600b. These are architectural targets; no pseudo-ASM pass has been done for v2. BNTP v1's NormalBase pseudo-ASM landed at 4054b against a 3000b target — a 35% overshoot. If BNTP v2 follows a similar pattern, the Normal body could land at ~2700b, not 2000b. At 2700b, Normal UTXO would be ~2833b vs DSTAS ~3050b — still smaller but a narrower margin. This does not affect pain resolution scores (those are based on tx count and workflow structure), but it does affect the footprint-secondary score and long-term cost model. The pseudo-ASM pass (Phase 1 deliverable) is a critical validation gate.

**2. Depth threshold policy is unspecified.**
The spec says "off-chain advisory only" for freshness enforcement (§15, decision #7) — no CLTV-style on-chain expiry. This means depth thresholds are wallet-defined, not protocol-defined. Inconsistent policies across wallets and DEXes could create user confusion: token accepted by wallet A at depth 80, rejected by DEX B at depth 50. A protocol recommendation (not enforcement) for standard thresholds would help adoption.

**3. Royalty floor without ceiling is a governance gap.**
The protocol floor of 1 token unit prevents dust but does not bound the issuer's royalty. An issuer can charge any royalty. This is by design (off-chain policy), but it means users have no on-chain guarantee of fair pricing. Issuers in competitive markets self-regulate; monopoly issuers may not.

**4. Flex-transfer conservation relies on pushes matching hashPrevouts.**
The conservation mechanism binds `amounts_in_array` to `hashPrevouts` via a hash verification. If a wallet implementation incorrectly constructs `amounts_in_array`, the tx will fail at broadcast (script verification failure) — not silently. This is safe but may be a developer footgun if SDK validation is incomplete.

**5. External swap protocol impact is speculative.**
Section 3 (W6) estimates swap tx at ~4900b for BNTP v2 vs ~19 KB for DSTAS. These are estimates based on flex-transfer sizing. The actual external swap protocol may add overhead (cross-party negotiation output, swap identifier, timeout mechanism) that increases the size. The comparison stands qualitatively; the exact bytes are uncertain until the swap protocol is specified.

---

## 9. Recommendation

**Recommendation: Proceed to Phase 1 (build PoC), with two explicit gates before committing to full production.**

### Rationale

The primary pain metrics are decisive. BNTP v2 eliminates merge pain entirely (score: 1→5) and brings B2G verification from O(depth) to O(1) for fresh UTXOs (score: 1→4). These are genuine architectural wins that solve the stated production problems. The weighted pain score gap (61 vs 26.5) reflects a real and substantial improvement.

The risks (issuer liveness, royalty cost, adoption friction regression) are real but manageable. They are known upfront and do not invalidate the core pain resolution — they define the boundary of which token types benefit most.

### Phase 1 gates

**Gate A — Pseudo-ASM body size validation:**
Before committing to production, run the v2 Normal template through a pseudo-ASM pass equivalent to what was done for v1 NormalBase. Target: Normal body ≤ 2500b (accept up to 3000b with margin). If body lands above 3000b, revisit the path consolidation or optionalData handling. The v1 lesson (4054b vs 3000b target) must not be repeated.

**Gate B — Refresh economics validation with issuer pricing:**
Model a representative token (medium-frequency transfers, 5-year lifespan, 1000-unit typical UTXO) against 3 issuer pricing scenarios: (a) cost-plus 0.5% royalty; (b) market-rate 1% royalty; (c) high-frequency forced refresh (depth threshold 20). If scenario (c) makes the token economically worse than DSTAS, document the frequency threshold explicitly as a "not suitable for BNTP v2" criterion.

### Scope narrowing options (if Phase 1 resources are constrained)

If Phase 1 must be scoped down, the following priorities hold:

1. **Must have:** flex-transfer (1→M and N→M), issue, attestation/refresh. These cover the two primary pains and are non-negotiable for the value proposition.
2. **Phase 2:** Frozen template, freeze, confiscate, unfreeze. These cover compliance and are important but don't block the core pain demonstration.
3. **Phase 3:** MPKH paths. Important for enterprise adoption but not for initial PoC.
4. **Defer indefinitely:** external swap protocol specification. It is architecturally cleaner to do it right than fast. Phase 1 should not attempt to specify it.

### What not to do

Do not start Phase 1 work with the whitelist commitment from v1. BNTP v2 explicitly removed it (§5.4). Reintroducing it would add 128b to every UTXO and ~230b of verification logic without solving any of the target pains. The v1 analysis showed whitelist did not solve B2G and added cost.

Do not target footprint as a primary success metric for Phase 1. It is already a secondary metric in this spec, and chasing it during PoC delays the pain-resolution validation that matters.

---

## Appendix: Summary Scoring Table

| Workload                          | DSTAS tx count            | BNTP v2 tx count         | DSTAS bytes | BNTP v2 bytes             | Pain metric winner |
| --------------------------------- | ------------------------- | ------------------------ | ----------- | ------------------------- | ------------------ |
| W1: Pay 100 from mixed UTXOs      | 2-3                       | 1                        | ~13.3 KB    | ~2.6 KB                   | BNTP v2            |
| W2: Consolidate 10→1              | 9                         | 1-2                      | ~88 KB      | ~7 KB                     | BNTP v2            |
| W3: Receive + verify (fresh UTXO) | 0 tx but O(depth) network | 0 tx, O(1) lookup        | N/A         | N/A                       | BNTP v2            |
| W4: Send to DEX (fresh UTXO)      | 0 extra steps             | 0 extra steps            | ~3.5 KB     | ~2.4 KB                   | BNTP v2 (DEX-side) |
| W4: Send to DEX (stale UTXO)      | 0 extra steps             | 1 refresh tx             | ~3.5 KB     | ~2.4 KB + ~2.9 KB refresh | DSTAS              |
| W5: Refresh                       | N/A                       | 1 tx per refresh cycle   | N/A         | ~2.9 KB                   | N/A                |
| W6: Cross-token swap              | 1 tx (built-in)           | 1 tx (external protocol) | ~19 KB      | ~4.9 KB                   | BNTP v2            |
| W7: Compliance freeze             | 1 tx                      | 1 tx                     | ~3.6 KB     | ~1.2 KB                   | BNTP v2            |

---

_This document was produced as part of BNTP v2 pre-implementation research. See `BNTP_V2_SPEC.md` for the authoritative v2 specification and `BNTP_FULL_TX_FOOTPRINT_COMPARISON.md` for the prior v1 footprint analysis._
