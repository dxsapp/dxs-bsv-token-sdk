# BNTP v1 — Architectural Alternatives Evaluation

**Date:** 2026-04-17
**Author:** Research pass, post Phase 0 closeout
**Status:** Decision-support document. Not a spec.

---

## 1. Scope and Baseline

Phase 0 confirmed that a single monolithic Normal template carrying all 6 spend paths (transfer, split, merge-K, prepare-swap, freeze, confiscate, redeem) reaches ~4640b — nearly twice the 2400b budget. The optimized floor is ~3600b, still 50% over. The Phase 0 verdict was PIVOT, not ABORT.

The three immediate options identified in the closeout were:

- **Option A (recommended):** Split Normal → NormalBase (paths 1/2/4/5/6) + NormalSwapOnRamp (path 3). Whitelist expands to 4 templates. Rebaseline per-template budget to ~3000b.
- **Option B:** Drop prepare-swap entirely from v1. Normal shrinks to ~3200b; 2-template whitelist.
- **Option C:** Abort BNTP v1 and investigate alternatives.

This document evaluates Option A as the reference line alongside 7 architectural alternatives, to determine whether any of them strictly dominates Option A before committing to Phase 0.1 implementation work.

**DSTAS 1.0.4 baseline for comparison:** ~3050b per UTXO (2900b body + 150b tail area). BNTP v1's stated goal is ≥20% reduction on the most common case (Normal).

---

## 2. Alternative-by-Alternative Analysis

---

### 2.1 Option A — Split NormalBase + NormalSwapOnRamp (Reference Line)

**Architecture sketch.** Split the monolithic Normal into two templates: NormalBase carries transfer, split, merge-K, freeze, confiscate, and redeem (5 functional paths); NormalSwapOnRamp carries only prepare-swap (the path that requires issuer attestation and produces a SwapReady output). Whitelist grows from 3 to 4 templates (NormalBase, NormalSwapOnRamp, Frozen, SwapReady). Every template embeds a 128b whitelist block instead of 96b. All Phase 0-proven primitives (commitment scheme, anchor/follower) are reused unchanged.

**Template size estimate.** NormalBase PREFIX (~763b) + WHITELIST (128b) + SUFFIX stripped of swap path (~1800–2200b) + tail (~145b) = ~2900–3200b total. NormalSwapOnRamp is a narrower template: PREFIX (~500b covenant) + issuer attestation check (~150b) + WHITELIST (128b) + SwapReady output construction (~400b) + tail (~145b) = ~1300–1600b. Both within the ~3000b rebaseline.

**Novel primitives required.** None — whitelist commitment scheme and anchor/follower already proven sound in Phase 0.

**Key risks.**

- NormalBase still needs full anchor/follower merge logic; its SUFFIX remains the largest single block.
- 128b whitelist per UTXO instead of 96b — a 33b overhead increase on every live UTXO indefinitely.
- Issuer attestation mechanism requires spec redesign (Phase 0 surfaced that CHECKSIG-over-arbitrary-hash does not exist natively; needs null-data encoding approach from S1 SPEC AMENDMENT REQUEST #1).

**Pros.**

- Smallest scope change from the design already proven sound.
- DEX/swap story preserved (NormalSwapOnRamp is a dedicated, narrow, auditable template).
- All 11 SPEC AMENDMENT REQUESTs from Phase 0 are still applicable; no new unknowns introduced.

**Cons.**

- +1 template in whitelist vs original design; audit surface grows ~25%.
- Size savings vs DSTAS reduce from the originally claimed −28% on Normal to approximately −19% for NormalBase.
- Two separate template bodies must be maintained and kept consistent (shared tail layout, shared series constants).

**Scores.** Size: 4 | Ship-ability: 5 | Audit: 4 | Features: 5 | Trust: 5 | Wallet UX: 5 | Indexer: 5

---

### 2.2 Per-Spend-Path Templates

**Architecture sketch.** Each spend path becomes its own template. Candidate set: Normal-Transfer, Normal-Split, Normal-Merge2, Normal-Merge3, Normal-Merge4, Normal-Freeze, Normal-Confiscate, Normal-Redeem, Normal-PrepareSwap, Frozen-Unfreeze, Frozen-Confiscate, SwapReady-Execute, SwapReady-Cancel. State transition = template swap. A UTXO in state "Normal-Transfer" can only be spent via a transfer-specific unlocking script. The whitelist must enumerate all valid next-state templates, growing to 10–13 entries (~320–416b whitelist block).

**Template size estimate.** Each single-path template carries the full PREFIX (OP_PUSH_TX covenant + preimage parse = ~550b) but a tiny SUFFIX for its one path (~200–500b per path). Total per template: ~900–1200b. However, the whitelist block balloons to ~416b if 13 templates × 32b each. Effective on-chain footprint: ~1300–1600b per UTXO (smaller body, larger embedded constants).

**Novel primitives required.** None beyond existing OP_PUSH_TX covenant and hash-based whitelist.

**Key risks.**

- Whitelist grows quadratically with feature additions; ~416b whitelist block per UTXO partially cancels the body size savings.
- Wallet must select the correct next-state template before constructing the transaction. Transfer UTXOs cannot be merged; they first need a template-swap transaction to Normal-Merge. This adds mandatory "template rebrand" transactions that don't exist in Option A.
- Cross-path operations (e.g., split-then-freeze in one tx) require the wallet to chain two transactions, worsening UX and on-chain footprint.

**Pros.**

- Each template is tiny and trivially auditable in isolation.
- No path dispatch logic in script — the template IS the path, no branching required.
- Bugs are contained: a flaw in Normal-Freeze does not affect Normal-Transfer.

**Cons.**

- Template rebrand transactions for path changes cost additional on-chain fees and delay.
- Whitelist of 13 templates is ~4× larger than Option A's 4; commitment grows proportionally in every UTXO.
- Wallet and indexer complexity explodes: 13 template hashes to track vs 4.

**Scores.** Size: 3 | Ship-ability: 4 | Audit: 5 | Features: 4 | Trust: 5 | Wallet UX: 2 | Indexer: 3

---

### 2.3 Action UTXO Pattern

**Architecture sketch.** The Normal UTXO is reduced to a minimal state carrier (~400–600b): it holds owner PKH, tokenId, satoshi amount, and a whitelist of whitelisted "action" UTXO body hashes. The Normal script enforces only one rule: this UTXO must be spent in a transaction that also spends a UTXO whose locking script body hash is in the action whitelist. Each action UTXO (Transfer-Action, Merge-Action, Freeze-Action, etc.) is a singleton template whose script enforces the transformation semantics. The action UTXO is consumed (burned) in the same transaction. Token UTXOs never encode action logic; they merely require co-spend with a valid action UTXO.

**Template size estimate.** Normal UTXO: ~500–700b (covenant to verify co-spend with action UTXO). Action UTXOs: each ~600–900b (own OP_PUSH_TX covenant + path-specific output reconstruction). Tx requires 2 inputs minimum (Normal + Action). Net on-chain bytes per operation = ~1100–1600b across two UTXOs consumed, but only one Normal UTXO output (~500b) — overall comparable or slightly worse than Option A per tx for single-path ops.

**Novel primitives required.** Co-spend enforcement: the Normal script must verify that another specific input exists in the same transaction and has a matching script body hash. This requires reading another input's scriptCode from the preimage — which is NOT directly available via OP_PUSH_TX (preimage only covers the current input's scriptCode). Reconstructing another input's script requires the unlocking script to push the counterparty input's full script as a witness, plus a HASH256 check. This is a novel multi-input covenant composition that has not been deployed on BSV production and introduces new attack surfaces (malleation of the action UTXO content at signing time).

**Key risks.**

- Multi-input covenant composition is novel and unproven on BSV. The preimage covers `hashPrevouts` (commitment to all input outpoints) but not other inputs' scriptCodes. Verifying the action UTXO's script body from within Normal requires pushing its full script as witness data, which can be manipulated.
- Every token operation requires two UTXOs, doubling UTXO set entries and fee complexity.
- Action UTXOs must come from somewhere — issuer must supply them (fungible "stamps"), adding issuer liveness dependency for all operations.

**Pros.**

- Normal UTXO itself becomes very small and uniform — only state, no path logic.
- Action templates can be audited, upgraded, and extended without touching Normal UTXOs.
- Conceptually clean separation of identity (Normal) from behavior (Action).

**Cons.**

- The core co-spend enforcement mechanism is not achievable cleanly with current BSV Script introspection — a fundamental blocker.
- Every operation consumes two UTXOs and produces at least one, increasing tx size and fee.
- Issuer must supply action UTXOs as a service; action UTXO exhaustion = protocol halt.

**Scores.** Size: 3 | Ship-ability: 1 | Audit: 3 | Features: 3 | Trust: 3 | Wallet UX: 2 | Indexer: 3

---

### 2.4 sCrypt-Compiled Templates

**Architecture sketch.** Write the BNTP Normal (and other template) logic in sCrypt, a TypeScript-like high-level DSL that compiles to BSV Script opcodes. Use sCrypt stdlib for HashedMap, sighash helpers, and common preimage parsing. Claim a 10–30% size reduction from compiler optimizations vs hand-written opcode sequences.

**Template size estimate.** sCrypt generates BSV Script. It is bounded by the same opcode semantics, stack constraints, and Script encoding rules as hand-written code. sCrypt's optimizer can eliminate redundant OP_DUP/OP_SWAP patterns and inline common sub-expressions, but it cannot eliminate the structural overhead: OP_PUSH_TX covenant (~350b), preimage parse (~180b), output reconstruction (~300b per output), and serialization constants (~50b) are irreducible. Realistically, sCrypt might reduce the hand-optimized DSTAS-derived body from ~3600b to ~3000–3200b — roughly matching Option A's rebaseline, not beating it. The "10–30% smaller than hand-written" claim applies to unoptimized hand-written code, not to audit-grade manually-optimized code as produced in Phase 0 S1.

**Novel primitives required.** None — sCrypt compiles to standard BSV Script opcodes.

**Key risks.**

- sCrypt compiler output is harder to audit than hand-written pseudo-ASM: reviewers must either trust the compiler or decompile the output to verify correctness.
- Compiler version lock-in: script byte-for-byte content determines the body hash (h_Normal); any compiler upgrade silently changes h_Normal and breaks the whitelist commitment for all deployed UTXOs.
- sCrypt's HashedMap and preimage utilities may introduce their own overhead that exceeds the savings from expression-level optimization.

**Pros.**

- Faster development cycle: sCrypt IDE provides simulation, unit tests, and type checking.
- Reduces human opcode-level errors vs writing pseudo-ASM by hand.
- sCrypt has an existing community and production deployments on BSV.

**Cons.**

- Does not solve the fundamental size problem — sCrypt is not magic compression. Best case matches Option A's size target, worse case adds overhead.
- Compiler-generated output is a black box for security auditors unfamiliar with sCrypt IR.
- Locks the project into sCrypt toolchain dependencies; any toolchain abandonment is a serious maintenance risk.

**Scores.** Size: 3 | Ship-ability: 4 | Audit: 3 | Features: 5 | Trust: 5 | Wallet UX: 5 | Indexer: 5

---

### 2.5 OP_CODESEPARATOR Code Sharing

**Architecture sketch.** Use OP_CODESEPARATOR to partition templates into a shared PREFIX section (OP_PUSH_TX covenant, preimage parse, output verification helpers, ~550b) and a per-template SUFFIX (path-specific logic). The shared PREFIX is authored once as a canonical byte sequence and embedded literally in each template. On-chain, OP_CODESEPARATOR makes `scriptCode` for sighash computation start at the separator position, so templates remain distinguishable post-separation. The idea is to eliminate the "copy this 550b block into every template" duplication and reference it via a known UTXO or inline constant.

**Template size estimate.** OP_CODESEPARATOR does NOT remove opcodes from the template — it changes only what portion of the script is included in `scriptCode` for sighash. Every template still physically contains the full PREFIX + SUFFIX bytes on-chain. There is no "shared library" mechanism in BSV Script. Duplication is physical and unavoidable. OP_CODESEPARATOR buys template distinguishability at zero extra bytes, but saves 0 bytes of PREFIX duplication. Effective size: identical to Option A.

**Novel primitives required.** None — OP_CODESEPARATOR is a standard opcode.

**Key risks.**

- The premise is based on a misunderstanding: OP_CODESEPARATOR does not allow physical byte-sharing between UTXOs. Each UTXO stores its full script. Deduplication in UTXO storage is a node implementation detail, not a consensus property.
- Using OP_CODESEPARATOR to modify scriptCode scope interacts non-trivially with OP_PUSH_TX's covenant mechanism (which depends on knowing the exact scriptCode). This interaction needs careful analysis and could introduce subtle covenant-breaking bugs.
- This technique adds complexity with no measurable size benefit on-chain.

**Pros.**

- OP_CODESEPARATOR is an existing opcode — no new consensus changes needed.
- Could simplify template distinguishability in output verification (slight simplification vs body-marker approach).
- Zero additional on-chain bytes for the separator itself.

**Cons.**

- Provides zero on-chain size reduction — the core problem is not solved.
- Interacts with OP_PUSH_TX covenant in subtle ways that require additional analysis.
- A pure engineering complexity addition with no net benefit over Option A.

**Scores.** Size: 4 | Ship-ability: 4 | Audit: 3 | Features: 5 | Trust: 5 | Wallet UX: 5 | Indexer: 5

---

### 2.6 Two-UTXO Metadata + Value Split

**Architecture sketch.** Each token is represented by two co-owned UTXOs: (a) a metadata UTXO holding 1 satoshi + owner + state + tokenId + covenant enforcing paired spend with the value UTXO (~500b); (b) a value UTXO holding actual token satoshis + a covenant that forces spend alongside the matching metadata UTXO (~400b). Operations must consume both and produce both. Identity and value are separated on-chain.

**Template size estimate.** Metadata UTXO: ~500b (covenant checking paired spend + UTXO-set identity commit). Value UTXO: ~400b (satoshi conservation + paired-spend lock). Total per token: ~900b across two UTXOs. However, enforcing "paired spend" from within the value UTXO faces the same problem as the Action UTXO pattern: BSV Script OP_PUSH_TX does not expose other inputs' scriptCodes. The pairing mechanism must rely on a tokenId embedded in both UTXOs and verified against a common unlocking witness, not cryptographic co-spend enforcement. This weakens the guarantee: a miner or attacker who can construct a transaction satisfying both scripts separately may be able to split the pair.

**Novel primitives required.** Reliable cross-input pairing: verifying that two specific UTXOs are spent together in the same transaction is not achievable via OP_PUSH_TX alone without the other input pushing its full script as witness data (same limitation as 2.3). Additionally, UTXO set bloat doubles: every token issuance now creates 2 UTXOs; every operation consumes 2 and produces 2.

**Key risks.**

- Cross-input pairing enforcement is not achievable with current BSV Script introspection. The design degrades to "soft pairing via convention" without a cryptographic guarantee.
- UTXO set doubles; this increases node resource consumption and fee cost per operation.
- Wallet must always know and manage pairs; a wallet that loses one half of the pair has a partially unspendable token — severe UX failure mode.

**Pros.**

- Metadata UTXO could be very small and uniform across all token states.
- Value UTXO's script could be simpler because it offloads identity logic to metadata UTXO.
- Conceptual separation of "who owns this" from "how much is this" mirrors ERC-20 account model.

**Cons.**

- Enforcement gap: pairing cannot be cryptographically guaranteed with current BSV Script.
- UX is significantly worse: wallets must track pairs, display balances from two UTXOs, handle pair-loss scenarios.
- No meaningful size improvement over Option A once paired-spend enforcement is added.

**Scores.** Size: 3 | Ship-ability: 2 | Audit: 2 | Features: 3 | Trust: 3 | Wallet UX: 1 | Indexer: 2

---

### 2.7 Multi-Tx Spend Flow (Intent + Execute)

**Architecture sketch.** Operations are split across two sequential transactions. Phase 1 (intent): owner creates an "intent UTXO" (~700b script) that commits to the desired transformation: output addresses, amounts, path_id, and a hash of the expected resulting UTXOs. Phase 2 (execute): the intent UTXO is spent together with the Normal UTXO to execute the transformation. Normal's script is reduced to ~1200–1500b because most path-specific logic lives in the ephemeral intent UTXO.

**Template size estimate.** Normal: ~1500b (PREFIX covenant + preimage parse + co-spend verification against intent hash). Intent UTXO: ~700b (owner sig + intended output commitment). Per operation: 2 transactions, total ~2200b of script consumed + new Normal UTXO produced (~1500b). Net footprint per final result: ~1500b Normal + 1 extra mempool tx (fees doubled).

**Novel primitives required.** Same co-spend verification problem: Normal must verify that its companion intent UTXO encodes the correct transformation, which requires reading another input's scriptCode from within Normal — not supported by OP_PUSH_TX alone. The intent UTXO must push its own script as witness, which the Normal script then hashes and verifies against an embedded commitment. This is a weaker-than-ideal guarantee (trusts the unlocking script to present the correct intent body) and requires careful design to prevent substitution attacks.

**Key risks.**

- Two-transaction flows double the fee cost and confirmation latency for every token operation.
- Intent UTXOs are time-locked or use-once by design — intent mempool management adds wallet complexity.
- If the intent UTXO is front-run or its companion Normal is double-spent between phase 1 and phase 2, the operation fails atomically (safe), but user experience degrades to "sometimes operations just fail."

**Pros.**

- Normal UTXO becomes meaningfully smaller (~1500b vs ~3000b).
- Intent UTXOs are ephemeral and don't accumulate in the UTXO set long-term.
- Separation of "declare intent" from "execute" could enable better wallet UX (preview before commit).

**Cons.**

- Every operation costs 2 confirmations instead of 1 in BSV (or 2 mempool transactions with chaining).
- Co-spend enforcement has the same introspection limitation as alternatives 2.3 and 2.6 — the core mechanism is unproven.
- The latency cost is real: BSV has ~1 block confirmation times but sequential chaining still adds latency and complexity.

**Scores.** Size: 4 | Ship-ability: 2 | Audit: 3 | Features: 4 | Trust: 4 | Wallet UX: 2 | Indexer: 3

---

### 2.8 Stateless Token + Off-Chain Proof

**Architecture sketch.** Remove all covenant logic from the UTXO. A token is simply a chain of transactions starting from a genesis UTXO. The current holder holds a P2PKH UTXO (25b script) and an off-chain "provenance proof" — an ordered list of transaction IDs + output indices forming the unbroken chain back to genesis. Transfers are plain P2PKH sends. The receiver's wallet verifies the chain off-chain before accepting. Bitcoin (BSV) is used only for settlement and timestamping, not enforcement.

**Template size estimate.** P2PKH UTXO: 25b. Provenance proof grows linearly with token age: after 1000 transfers, the proof is ~1000 × 36b (outpoints) = ~36KB transferred out-of-band. No on-chain script overhead beyond P2PKH.

**Novel primitives required.** None on-chain. Off-chain: a robust provenance proof format, chain of custody signing, and indexer infrastructure to serve and verify proofs. This is equivalent to rebuilding DSTAS's off-chain validation layer without DSTAS's on-chain closed-state guarantees.

**Key risks.**

- Zero on-chain enforcement: any receiver who skips off-chain verification accepts counterfeit tokens. Security depends entirely on wallets being correct and honest.
- Provenance proof distribution is an unsolved protocol problem: who stores it, who serves it, what happens when the original issuer's indexer goes offline?
- The model is strictly weaker than DSTAS 1.0.4, which at least provides closed-forward state via on-chain covenant. This is a regression, not a progression.

**Pros.**

- Smallest possible on-chain footprint: P2PKH + arbitrary satoshis.
- Maximum flexibility: no protocol constraints, any wallet can participate.
- Fastest to implement: no novel script work at all.

**Cons.**

- Provides none of BNTP's defined security properties. This is not a token protocol — it is an off-chain data protocol that happens to use BSV UTXOs for settlement.
- Incompatible with DEX flows that require on-chain atomic swap guarantees.
- Provenance proofs grow unboundedly; long-lived high-velocity tokens become impractical.

**Scores.** Size: 5 | Ship-ability: 5 | Audit: 5 | Features: 1 | Trust: 1 | Wallet UX: 3 | Indexer: 1

---

## 3. Scored Matrix

| Candidate                                   | Size | Ship-ability | Audit | Features | Trust | Wallet UX | Indexer | **Total** |
| ------------------------------------------- | :--: | :----------: | :---: | :------: | :---: | :-------: | :-----: | :-------: |
| A. Option A (NormalBase + NormalSwapOnRamp) |  4   |      5       |   4   |    5     |   5   |     5     |    5    |  **33**   |
| B. Per-spend-path templates                 |  3   |      4       |   5   |    4     |   5   |     2     |    3    |  **26**   |
| C. Action UTXO pattern                      |  3   |      1       |   3   |    3     |   3   |     2     |    3    |  **18**   |
| D. sCrypt-compiled templates                |  3   |      4       |   3   |    5     |   5   |     5     |    5    |  **30**   |
| E. OP_CODESEPARATOR sharing                 |  4   |      4       |   3   |    5     |   5   |     5     |    5    |  **31**   |
| F. Two-UTXO metadata + value                |  3   |      2       |   2   |    3     |   3   |     1     |    2    |  **16**   |
| G. Multi-tx intent + execute                |  4   |      2       |   3   |    4     |   4   |     2     |    3    |  **22**   |
| H. Stateless + off-chain proof              |  5   |      5       |   5   |    1     |   1   |     3     |    1    |  **21**   |

**Scoring note.** All axes are weighted equally (1–5, higher is better). No differential weighting applied — the project context (covenant-enforced token protocol on BSV) makes feature coverage, ship-ability, and trust model roughly equally critical for production use.

---

## 4. Top 3 Ranked

### Rank 1: Option A — NormalBase + NormalSwapOnRamp (Score: 33)

**Why it ranks first.** Option A is the only candidate that scores 5 across ship-ability, feature coverage, trust model, wallet UX, and indexer complexity simultaneously. It inherits all Phase 0-proven sound primitives. The only meaningful sacrifice vs the original design is a 33b whitelist expansion per UTXO and a modest reduction in size savings vs DSTAS (from −28% to approximately −19%). Every other candidate with comparable feature coverage either has worse ship-ability, introduces unproven primitives, or adds operational complexity.

**When this is the right choice.** Option A is the right choice when BNTP v1 needs to ship on the current BSV opcode set with no external dependencies, full feature coverage, and a defensible trust model. This covers every realistic production deployment scenario for BNTP v1.

**What must be proven in Phase 0.2 before committing.**

- NormalBase body can be held within ~3000b (pseudo-ASM level verification, not just estimation).
- Issuer attestation redesign (S1 SPEC AMENDMENT REQUEST #1 resolution) is implementable without adding more than ~150b to NormalSwapOnRamp.
- 4-template whitelist (128b) fits comfortably in every template body without pushing any over 3200b.

---

### Rank 2: OP_CODESEPARATOR Sharing (Score: 31)

**Why it ranks second.** OP_CODESEPARATOR does not solve the size problem (physical PREFIX bytes still appear in every template), but it scores identically to Option A on all non-size axes. It is fully shippable with current opcodes, does not require novel primitives, and does not degrade features, trust, or UX. It ranks second because it is a valid enhancement that can be layered on top of Option A, not a standalone competitor. The score difference (31 vs 33) entirely comes from the Audit axis (one point lower due to OP_CODESEPARATOR's interaction complexity with the OP_PUSH_TX covenant mechanism).

**When this is the right choice.** Not a standalone alternative — best used as a complementary technique inside Option A if body marker distinguishability becomes a concern. Evaluating it as a pure replacement is a mistake; it provides no size benefit.

**What must be proven before committing.** The interaction between OP_CODESEPARATOR position and OP_PUSH_TX's scriptCode hashing must be formally traced. If the sighash scriptCode scope shift creates a covenant bypass vector, OP_CODESEPARATOR should not be used at all.

---

### Rank 3: sCrypt-Compiled Templates (Score: 30)

**Why it ranks third.** sCrypt scores identically to Option A on features, trust, wallet UX, and indexer complexity, but falls short on size (same or marginally smaller than Option A's target, not better) and audit (compiler output is less transparent than hand-written pseudo-ASM). It ranks third because it represents a viable parallel development path: if the Option A pseudo-ASM work proves impractical to maintain long-term, a sCrypt implementation provides developer tooling, testing infrastructure, and error prevention that hand-written opcodes cannot match.

**When this is the right choice.** sCrypt is the right choice if the BNTP team decides that developer velocity and tooling outweigh the audit transparency of raw pseudo-ASM, and if sCrypt's compiler-emitted output has been independently verified against the hand-written body size targets. It is not a safe choice if the project lacks sCrypt expertise or if the compiler toolchain cannot be pinned and version-locked.

**What must be proven before committing.** A sCrypt prototype of the NormalBase body must be compiled and the output byte-counted against the Option A target (~3000b). If sCrypt output is within 5% of the hand-written estimate AND the compiler version can be pinned and audited, the tooling benefits justify the switch.

---

## 5. Red-Flag Candidates

**F — Two-UTXO Metadata + Value Split (Score: 16) — DO NOT PROCEED.**
This design fundamentally requires cross-input co-spend enforcement, which is not achievable with current BSV Script introspection (OP_PUSH_TX only exposes the current input's preimage). Without a cryptographic pairing guarantee, the "two-UTXO" invariant degrades to a convention that wallets can bypass. This is a security regression vs DSTAS, not an improvement. The UTXO-doubling overhead and UX impact (wallet must always manage pairs) compound the problem. No path to production readiness exists without BSV consensus changes.

**C — Action UTXO Pattern (Score: 18) — AVOID.**
Conceptually elegant but has the same cross-input enforcement limitation as candidate F. The Normal UTXO cannot cryptographically verify that an action UTXO was spent alongside it using current BSV Script primitives. Additionally, the requirement for an issuer to supply action UTXOs as a service introduces a new liveness dependency beyond issuer attestation — if the issuer stops minting action UTXOs, all token operations halt. The design introduces more complexity and more trust assumptions than Option A while solving a problem (audit isolation per path) that Option A already partially addresses through template splitting.

**H — Stateless + Off-Chain Proof (Score: 21) — REJECT AS BNTP.**
Stateless off-chain proof is a legitimate pattern for some use cases (e.g., colored-coin-style tokens where trust comes from social consensus, not script enforcement). However, it satisfies none of BNTP's defining design goals: no closed forward state, no on-chain authority enforcement, no DEX-compatible atomic swap, no confiscation/freeze. Scores 5 on size and ship-ability because it is trivially easy — but those are degenerate scores, achieved by simply not implementing a token protocol. Recommending this would mean abandoning BNTP entirely.

---

## 6. Honest Caveats

**Size estimates are approximations.** The template size estimates in this document are derived from Phase 0 S1 pseudo-ASM analysis plus extrapolation. They have not been byte-counted at the opcode level for candidates B through H. Estimates carry ±200–400b uncertainty. Before acting on size rankings, at minimum Options B and D should be sketched to opcode depth for the NormalBase-equivalent path.

**sCrypt output size is unverified.** The sCrypt claim of "10–30% smaller than hand-written" has not been tested against the BNTP-specific logic. This evaluation conservatively assumes sCrypt matches Option A's size target, not beats it. An actual sCrypt prototype would resolve this uncertainty quickly (a few hours of work).

**Cross-input enforcement limitation.** Candidates C, F, and G are all penalized for the same limitation: BSV Script's OP_PUSH_TX preimage does not expose other inputs' scriptCodes. This is a consensus-level constraint. If BSV were to introduce a cross-input introspection opcode (analogous to CTV-style covenant proposals in Bitcoin), candidates C and G would become significantly more viable. This evaluation is correct for the current BSV opcode set.

**Anchor/follower merge in NormalBase.** Option A's NormalBase still includes the anchor/follower pattern for merge-K. Phase 0 S3 proved this sound under 7 attack scenarios, but the algorithm has never been deployed in production. This is the highest remaining risk in Option A and should be the first thing formalized in Phase 0.2.

**Trust model scores.** "Trust: 5" for Options A, B, D, E does not mean zero trust is required — it means trust is bounded by Bitcoin consensus alone (no oracles, no federations). Issuer attestation in Option A's NormalSwapOnRamp is a trust assumption, but it is an acknowledged and scoped one: it affects only the prepare-swap path, and issuer compromise affects only future attestations, not historical token state.

---

## 7. Next-Step Recommendation

**Proceed with Option A. No alternative strictly dominates it.**

The alternatives analysis yields a clear result: among candidates that actually satisfy BNTP v1's feature requirements (closed forward state, on-chain authority enforcement, DEX-compatible swap flow, merge-K), Option A is the only one implementable with current BSV opcodes without novel unproven primitives. Candidates that score higher on individual axes (per-path templates on audit; sCrypt on developer velocity) do so by trading off other axes that are equally important for production use.

Concrete recommendation for Phase 0.1:

1. Accept Option A as the architectural baseline.
2. Resolve the 11 SPEC AMENDMENT REQUESTs from Phase 0 (prioritize S1 AMR #1 — issuer attestation redesign — as it gates NormalSwapOnRamp feasibility).
3. Produce NormalBase pseudo-ASM to opcode depth (not just structural estimate) and byte-count it against the 3000b target. This is the single most important unknown remaining.
4. If NormalBase pseudo-ASM comes out at 2800–3200b, proceed to Phase 1 skeleton.
5. If NormalBase pseudo-ASM exceeds 3400b, revisit Option B (drop prepare-swap) before spending more engineering effort on Option A.

**The sCrypt alternative (D) should be kept as a fallback.** If hand-written pseudo-ASM proves operationally unsustainable during Phase 1, a sCrypt prototype can be benchmarked quickly. It is not a better choice today, but it is a viable contingency that does not require fundamental redesign.
