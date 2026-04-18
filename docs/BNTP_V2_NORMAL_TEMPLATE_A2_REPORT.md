# BNTP v2 Normal Template — A.2 Real ASM Report (paths 2, 3, 4)

**Status:** Phase 1 Step A.2 execution report. Real BSV Script ASM for Normal template paths 2 (refresh), 3 (freeze), 4 (confiscate) SUFFIXes, replacing A.1.1's `OP_FALSE OP_VERIFY` stubs. Compiled via `asmToBytes`, measured byte-exact.

**Date:** 2026-04-18

**Artifact:**

- `src/bntp/v2/templates/normal-body.ts` — adds `PATH2_REFRESH_ASM`, `PATH3_FREEZE_ASM`, `PATH4_CONFISCATE_ASM`, `H_FROZEN_PLACEHOLDER_HEX`, `VARINT_SERIALIZE_ASM` helper, and `authorityIdentityAsm(flag)` parametric helper. Wires them into `DISPATCHER_MIDDLE_ASM` in place of the A.1.1 stubs. Extends `NORMAL_BODY_SECTION_SIZES` with `path2Refresh`, `path3Freeze`, `path4Confiscate` entries; `dispatcherMiddle` is re-computed as dispatcher overhead net of path bodies so the per-section sum still equals total body size.
- `tests/bntp-v2-normal-template-size.test.ts` — adds a sanity assertion that each A.2 path measures > 50b (guards against stub regression). Existing assertions (deterministic compile, marker, ABORT ceiling, regression floor, section sum, G5 verdict, diagnostic) kept intact.

---

## 1. Verdict

- **Measured body size:** **2587 bytes**
- **A.1.1 baseline:** 1901 bytes
- **A.2 delta:** +686 bytes (paths 2, 3, 4 minus 6b of removed stubs)
- **G5 gate:** PASS ≤ 2600 / PIVOT 2600-2700 / ABORT > 2700
- **Verdict:** **PASS** (13 bytes under the PASS ceiling; 113 bytes under ABORT)

The A.1.1 report projected 2711-2821b for the full body post-A.2, landing in PIVOT or just above ABORT. Measured outcome at **2587b** beats the projection by ~130-230b. Key driver: varint-length-branch simplification (see §3).

---

## 2. Per-path measurement

| Path                             | Audit estimate | Pseudo-ASM §4.2-§4.4 | Measured | Deviation vs pseudo | Notes                                                                             |
| -------------------------------- | -------------- | -------------------- | -------- | ------------------- | --------------------------------------------------------------------------------- |
| Path 2 — refresh                 | 320-380        | 409                  | **223**  | −186                | Two-output reconstruction trimmed by FD-only varint + fixed new_depth=0           |
| Path 3 — freeze                  | 280-310        | 275                  | **248**  | −27                 | Includes 32b `h_Frozen` placeholder (+33b direct push), on-target                 |
| Path 4 — confiscate              | 210-230        | 213                  | **221**  | +8                  | Same-template reconstruction; marginally over audit upper bound, within tolerance |
| **A.2 SUFFIX subtotal**          | **810-920**    | **897**              | **692**  | **−205**            | Under audit low-end by ~118b                                                      |
| Stubs removed (A.1.1 OP_FALSE×3) | —              | —                    | **−6**   | —                   | Each stub was 2b (OP_FALSE + OP_VERIFY)                                           |
| Dispatcher middle (overhead)     | —              | —                    | **17**   | —                   | Three OP_DUP/OP_EQUAL/OP_IF gates + OP_DROP                                       |
| **A.2 net delta**                |                |                      | **+686** |                     |                                                                                   |
| **A.1.1 baseline**               |                |                      | **1901** |                     |                                                                                   |
| **GRAND TOTAL (A.1.1+A.2)**      | —              | **2358**             | **2587** | +229                |                                                                                   |

Sum verified: per-section entries in `NORMAL_BODY_SECTION_SIZES` sum exactly to `NORMAL_BODY_SIZE = 2587`.

Per-section breakdown (complete body, after A.2):

| Section               | Bytes    |
| --------------------- | -------- |
| bodyMarker            | 5        |
| covenantPreamble      | 197      |
| covenantTail          | 241      |
| sighashCheck          | 13       |
| preimageParse         | 121      |
| tailCache             | 164      |
| ownerIdentity         | 110      |
| dispatcherHeader      | 9        |
| path1HashprevoutsBind | 8        |
| path1NDerive          | 23       |
| path1SelfposOutpoint  | 17       |
| path1AmountsArray     | 28       |
| path1MCheck           | 9        |
| path1DepthCheck       | 18       |
| path1SumInputs        | 120      |
| path1SumOutputs       | 108      |
| path1OutputRecon      | 620      |
| path1HashoutputsClose | 67       |
| **path2Refresh**      | **223**  |
| **path3Freeze**       | **248**  |
| **path4Confiscate**   | **221**  |
| dispatcherMiddle      | 17       |
| **TOTAL**             | **2587** |

---

## 3. Implementation notes

### 3.1 Key optimization: varint-length single-branch (FD-only)

The per-output candidate locking script in BNTP v2 is always between ~2000 and ~3000 bytes (body marker + covenant + preimage parse + tail cache + owner identity + dispatcher + all four path SUFFIXes + OP_RETURN + tail). This puts the output-serialization varint unambiguously in the `0xFD + 2-byte LE length` range.

A.1.1's `PATH1_OUTPUT_ONE_ASM` encodes the full three-branch varint selector (`FC00 / FFFF / FFFFFFFF`) per iteration, costing ~65b per reconstruction. A.2's shared `VARINT_SERIALIZE_ASM` helper emits only the FD branch, landing at **25 bytes**. Applied across 4 reconstructions in A.2 (2× path 2 + 1× path 3 + 1× path 4), this saves ~160b cumulative vs the path-1 pattern.

Correctness caveat: if a future locking script drifts outside the `[0xFD .. 0xFFFF]` range (e.g., massive optionalData bloat pushing bodies > 64KB), the varint would malform and `hashOutputs` would fail byte-exact match. SDK pre-validation must reject such cases before broadcast.

**Retro-applicable.** Path 1's three-branch varint can be similarly trimmed in a future optimization pass, saving ~120b from `path1OutputRecon` (620b → ~500b), bringing total body to ~2467b (deeper in PASS).

### 3.2 Authority identity + CHECKSIG(VERIFY) block

Per spec §8.1 / decision #29, freeze / confisc / issuer authorities require TWO independent checks: `HASH160(pubkey) == expected_hash` AND explicit `CHECKSIGVERIFY` against preimage. A parametric helper `authorityIdentityAsm(flagMaskHex)` produces the full block, branching PKH vs MPKH on the supplied flag bit (`0x04` for freeze, `0x08` for confisc, `0x10` for issuer).

Measured: **101 bytes per call** (PKH branch ~12b, MPKH branch ~75b including CHECKMULTISIGVERIFY with ×5 pubkey extraction gated on nonzero-length). Path 3 and path 4 each invoke once. Path 2 invokes differently for the issuer (verified via null-data pubkey, not via direct unlocking stack) — see §3.3 below.

### 3.3 Path 2 issuer verification divergence from pseudo-ASM

The spec (§9.3 rule 6-7) prescribes: parse null-data output at index 2 (`OP_FALSE OP_RETURN <tokenId 32b> <thisOutpoint 36b> <issuerPubkey 33b>`), extract the issuer pubkey from null-data, HASH160 match against `my.issuerPkh` from tail cache, then CHECKSIGVERIFY the issuer sig against the preimage.

A.2's implementation collapses this into ~65b of null-data parse + HASH160 + CHECKSIGVERIFY — shorter than pseudo-ASM's 70-100b claim because:

- Canonical push encoding (§7.2.1 Gap 4 closure) lets us stride the null-data bytes via fixed-offset splits (`20 OP_SPLIT`, `24 OP_SPLIT`, `21 OP_SPLIT`) rather than generic length-prefix parsing.
- The push-opcode bytes (`20`, `24`, `21`) are each trimmed via `OP_1 OP_SPLIT OP_NIP` instead of explicit byte-value EQUALVERIFY. Byte-exact hash commitment of the whole null-data through `hashOutputs` makes the per-byte equality checks redundant — any tampered byte fails final HASH256.

**Caveat — MPKH issuer branch omitted.** Spec §9.3 rule 6 mentions `HASH160(issuer_pubkey_as_MPKH_preimage)` as an alternate form gated by authorityFlags bit 4. A.2 implements only the PKH issuer branch. MPKH issuer extension is a future refinement (see §4.2 below); adding it would cost ~75b (mirroring `authorityIdentityAsm` MPKH branch). Current choice: accept PKH-only issuer as Phase 1 constraint; defer MPKH issuer to v2.1 or to a targeted refactor post-Phase-1B.

### 3.4 h_Frozen placeholder and deployer patching

The 32-byte `h_Frozen` constant is compiled in as 32 zero bytes. `H_FROZEN_PLACEHOLDER_HEX` is exported alongside the ASM to make the patch point discoverable. The SDK deployer (Phase 1B) must:

1. Compile the Frozen template body (separate artifact, not yet written).
2. Compute `SHA256(frozen_body_bytes)`.
3. Locate the placeholder in the compiled Normal body (byte offset derivable from the ASM layout) and overwrite in-place.

This mirrors spec §5.5.1 hash-commit + unlocking-body-push pattern. Keeps A.2's byte measurement honest while deferring the real hash to a build-time manifest step.

### 3.5 Stack-arithmetic caveats (unchanged from A.1.1 §3.3)

A.2 SUFFIX blocks are byte-measurable and structurally complete, but stack choreography across the altstack cache (populated in §3.5 tail cache) is **not formally verified**. The per-output reconstructions in paths 2, 3, 4 use the same `OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT` round-trip pattern as A.1.1's `PATH1_OUTPUT_ONE_ASM`, which is known to be an approximation (the exact altstack slot ordering is reset across path branches but has not been rigorously traced).

Phase 1B's SDK builder work will surface any stack bugs as unlocking-satisfaction failures. A.2's load-bearing contribution is the byte-budget measurement, not execution-proof.

---

## 4. Spec gaps discovered (for user review)

### 4.1 MPKH issuer branch is structurally specified but byte-budget gap is large

Spec §9.3 rule 6 describes the MPKH issuer case: `HASH160(issuer_pubkey_as_MPKH_preimage) == my.issuerPkh`. No issue with the normative text; but adding this branch to A.2's path 2 costs ~75b (mirroring the freeze/confisc MPKH branch). Current A.2 implementation **omits** this branch — PKH issuer only. If MPKH issuer is a required Phase-1 capability, budget impact is +75b → 2662b total (still PASS, but cutting PASS ceiling slack from 13b to −62b, forcing PIVOT).

**Recommendation for user:** decide before Phase 1B SDK builders whether MPKH issuer is required. If yes, accept PIVOT (+75b). If no, spec §9.3 should be amended to say "PKH issuer only in v2.0; MPKH issuer deferred to v2.1" so the gap is documented.

### 4.2 Null-data output index for path 2

Spec §9.3 rule 6 says the null-data output is at "index 2" (0-indexed: after output[0] refreshed and output[1] royalty). A.2 implementation tacitly assumes this — the `PATH2_REFRESH_ASM` parses a specific stack slot (via `OP_DEPTH OP_3 OP_SUB OP_PICK`) as the null-data bytes. Spec could be more explicit about the invariant.

**Recommendation:** spec §9.3 could add a sentence: "output[2] is the null-data attestation; SDK rejects refresh txs where the null-data is at a different index. Locking script relies on unlocking pushing null-data bytes as a specific stack slot, not on on-chain output-index parsing."

### 4.3 Freeze / confiscate null-data handling

Spec §9.4 and §9.5 show `[null-data?]` as an optional slot in the unlocking stack. A.2 does **not** currently emit ASM to append optional null-data into the hashOutputs accumulator for paths 3 and 4 (unlike path 1's `PATH1_HASHOUTPUTS_CLOSE_ASM` which has an explicit `OP_SIZE > 0` branch). For consistency, paths 3/4 should either (a) always require null-data push (promote to mandatory), or (b) add the optional-append branch.

**Impact:** current A.2 implicitly disallows null-data on freeze/confiscate. If that's intentional, spec should say so. If null-data is allowed but optional, A.2 needs ~25b per path to add the optional-append branch (paths 3 + 4 = +50b total → 2637b → still PASS).

**Recommendation:** user decides freeze/confiscate null-data policy. A.2 assumes "disallowed" (simplest) but will flag in the SDK builders if a tx includes null-data under these paths.

### 4.4 Change output handling in path 2

Spec §9.3 unlocking includes `[change_satoshis? change_script?]` — optional change output beyond the two BNTP outputs and null-data. A.2 does not emit change-append ASM; the refresh covenant will reject txs with any extra outputs beyond `[refreshed ‖ royalty ‖ null-data]`.

**Recommendation:** same as §4.3 — decide policy. If change is required (e.g., funding input > fees + dust), budget +30b to add the optional change-append branch. Current A.2: change disallowed. Phase 1B SDK should enforce "pay exact fee via funding input" pattern.

---

## 5. Recommendations for Step B / Step C

### 5.1 Proceed to Step C (adversarial review)

A.2 lands PASS with 13b headroom. Recommend moving to **Step C — adversarial review** of the combined A.1.1 + A.2 body:

- Execution-trace every path 1, 2, 3, 4 manually or via scriptic simulator to verify stack-correctness (this is the load-bearing deferred work from A.1.1 §3.3 and A.2 §3.5).
- Probe §4.1-§4.4 gaps above: user decides MPKH issuer, null-data policy for freeze/confiscate, change output handling.
- Validate `body_before_tail` offset resolution against a real example tx (Gap 4.2 in A.1.1 §4.2 is still open; Phase 1B deployer must pin offsets).

### 5.2 Optimization opportunities (optional; not blocking)

If a deeper PASS margin is desired:

- **Retroactive FD-only varint in path 1:** −120b (2587 → ~2467).
- **Preimage parse optimization (DSTAS §5.1.A/B pattern):** −30-50b.
- **Authority identity MPKH branch consolidation:** if MPKH authorities are rare (most deployments use PKH), gate the entire MPKH branch on a single top-level flag check and share bytes across paths. Requires block-level refactor. −100-150b potential but changes stack semantics.

Not recommended to pursue unless Step C surfaces MPKH issuer as required (forcing path 2 +75b).

### 5.3 Phase 1B SDK builder caveats

- **h_Frozen patching:** builder must resolve `H_FROZEN_PLACEHOLDER_HEX` → real `SHA256(Frozen body)` at deploy time. If Frozen body isn't yet written, A.2's compile still works (placeholder = 32 zero bytes); but broadcast-able txs cannot be constructed until Frozen body is finalized.
- **Unlocking script catalog for paths 2, 3, 4:** not yet written. Phase 1B must produce tx-builder helpers that push the exact stack layout specified in spec §9.3-§9.5.
- **Null-data canonical encoding enforcement (§7.2.1):** SDK must emit direct-push-minimal for tokenId/thisOutpoint/issuerPubkey. Non-canonical pushes will fail byte-exact hashOutputs match.

### 5.4 Spec amendment backlog (user review queue)

Not self-fixed per A.2's spec-frozen constraint:

1. MPKH issuer branch policy (§4.1 above)
2. Null-data index normative statement for path 2 (§4.2)
3. Freeze/confiscate null-data policy (§4.3)
4. Path 2 change output policy (§4.4)

None are blocking Step C. All can be resolved via spec amendment + ≤150b body delta, keeping PASS verdict achievable.

---

## 6. Next action

**Recommended:** proceed to **Step C — adversarial review** of A.1.1 + A.2 combined artifact (2587b). Step C owns:

- Manual execution trace of paths 1-4 (stack correctness).
- Probing the 4 spec gaps above to close open policy questions.
- Testing that `h_Frozen` patching mechanism works end-to-end (once Frozen body is written separately — likely Phase 1A.3).

**Alternative:** run an optimization pass (§5.2) before Step C to widen PASS margin. Only needed if Step C triggers a +75-150b addition that pushes total > 2600.

**Blocker status:** none. A.2 lands PASS. Phase 1B can start after Step C clears the combined body or in parallel with Step C on non-body components (wallet UX, indexer schema, etc.).

---

## Appendix — Validation run

Test runner blocked by environment (pre-existing ts-jest/jest version mismatch, documented in A.1.1 report §Appendix). Workaround: ran all test assertions via `npx tsx` inline script. Result:

```
NORMAL_BODY_SIZE: 2587
A.1.1 baseline: 1901
Delta: 686

Per-path (A.2):
  PATH2_REFRESH_ASM: 223
  PATH3_FREEZE_ASM: 248
  PATH4_CONFISCATE_ASM: 221

G5 verdict: PASS
marker (first 5): 4c 02 01 ff 75
section sum: 2587 == body size: true

 OK  body compiles deterministically
 OK  marker 0x4c 02 01 ff 75
 OK  body <= 2700
 OK  body >= 1500
 OK  section sum
 OK  path2 size > 50
 OK  path3 size > 50
 OK  path4 size > 50
 OK  verdict != ABORT

9/9 passed.
```

Compile is deterministic across independent passes. All section sums match. `H_FROZEN_PLACEHOLDER_HEX` export is the canonical 32-byte zero hex string (64 characters) ready for deployer patching.
