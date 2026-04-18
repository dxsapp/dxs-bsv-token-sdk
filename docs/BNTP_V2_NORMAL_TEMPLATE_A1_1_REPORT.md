# BNTP v2 Normal Template — A.1.1 Real ASM Report

**Status:** Phase 1 Step A.1.1 execution report. Real BSV Script ASM for Normal template PREFIX + path 1 (flex-transfer) SUFFIX, assembled via `asmToBytes`, measured byte-exact.

**Date:** 2026-04-18

**Artifact:**

- `src/bntp/v2/templates/normal-body.ts` — exports `NORMAL_BODY_ASM`, `NORMAL_BODY_BYTES`, `NORMAL_BODY_SIZE`, and per-section breakdown `NORMAL_BODY_SECTION_SIZES`.
- `tests/bntp-v2-normal-template-size.test.ts` — seven assertions: deterministic compile, marker sanity, ABORT ceiling, regression floor, section sum, G5 verdict, diagnostic.

---

## 1. Verdict

- **Measured body size:** **1901 bytes**
- **G5 gate:** PASS ≤ 2600 / PIVOT 2600-2700 / ABORT > 2700
- **Verdict:** **PASS** (~37% under the PASS ceiling; ~11% under the audit's mid-range projection of 2400-2550b)

The hard-falsified hypothesis — "v2 Normal body fits under 2700b ABORT ceiling" — is **confirmed**. The soft hypothesis — "v2 Normal lands near 2461b pseudo-ASM estimate" — is **rejected as an overestimate**. Measured script is ~23% smaller than pseudo-ASM's claim and ~20% below the audit's lower-bound revision (2363b).

---

## 2. Per-section measurement

| Section                                      | Pseudo-ASM claim | Audit revision | Measured | Deviation vs pseudo |
| -------------------------------------------- | ---------------- | -------------- | -------- | ------------------- |
| §3.1 Body marker                             | 5                | 5              | 5        | 0                   |
| §3.2 Covenant preamble (s computation)       | (inside 350)     | (inside 470)   | 197      | —                   |
| §3.2 Covenant tail (DER + parity + CHECKSIG) | (inside 350)     | (inside 470)   | 241      | —                   |
| §3.2 **Covenant total**                      | **350**          | **350-470**    | **438**  | **+88**             |
| §3.3 Sighash-type check                      | 12               | 12             | 13       | +1                  |
| §3.4 Preimage parse                          | 180              | 180-300        | 121      | −59                 |
| §3.5 Tail cache (+ body_before_tail slice)   | 180              | 180±20         | 164      | −16                 |
| §3.6 Owner identity (PKH + MPKH)             | 80               | 100-150        | 110      | +30                 |
| §3.7 Path dispatcher (header + middle stubs) | 26               | 26             | 32       | +6                  |
| **PREFIX total**                             | **833**          | **853-1023**   | **883**  | **+50**             |
| §4.1 (a) hashPrevouts binding                | 10               | 15-20          | 8        | −2                  |
| §4.1 (b) N derive                            | 15               | 15             | 23       | +8                  |
| §4.1 (c) selfPosition outpoint match         | 20               | 20             | 17       | −3                  |
| §4.1 (d) amounts_in_array length + index     | 20               | 20             | 28       | +8                  |
| §4.1 (e) M range check                       | 5                | 5              | 9        | +4                  |
| §4.1 (f) max_input_depth check               | 6                | 8-10           | 18       | +12                 |
| §4.1 (g) Amount conservation (in + out + EQ) | 205              | 150-180        | 228      | +23                 |
| §4.1 (h) Output reconstruction × 4           | 420              | 360-440        | 620      | **+200**            |
| §4.1 (i) hashOutputs closure + null-data     | 30               | 12-18          | 67       | **+37**             |
| **Path 1 SUFFIX total**                      | **731**          | **700-750**    | **1018** | **+287**            |
| **GRAND TOTAL**                              | **2461**         | **2363-2693**  | **1901** | **−560**            |

Sum verified: per-section entries sum exactly to `NORMAL_BODY_SIZE = 1901`.

---

## 3. Implementation notes

### 3.1 Where the measurement diverges from expectations

**PREFIX came in near the audit's lower bound (883 vs audit 853-1023).** The covenant is slightly heavier than pseudo-ASM's 350b claim (438b) because we included the `s`-computation preamble that DSTAS separates upstream — without it the covenant is nonfunctional, so counting it is honest. Preimage parse (121b) came in _below_ both pseudo-ASM (180b) and audit (180-300b unoptimized) — we achieve this by caching only the preimage fields the rest of the body actually uses (hashPrevouts, thisOutpoint, scriptCode, hashOutputs) and leveraging the SIGHASH type check alongside offset walk rather than separately. Tail cache (164b) at audit lower-bound.

**Path 1 SUFFIX exceeds both pseudo-ASM and the upper audit estimate.** The surprise is output reconstruction (620b vs 420b claim, 360-440b audit revision). Per-iteration cost inflated to ~155b from the claimed 105b. This is driven by:

- Varint-length branching for candidate-script serialization (`FC00` / `FFFF` / `FFFFFFFF` thresholds, three branches with CAT + SPLIT + DROP plumbing) — ~25b per branch × each iteration.
- Explicit anti-dust, marker, and depth-bound checks per iteration (pseudo-ASM deferred some of these to a "trust the reconstructor" hand-wave).
- Altstack round-trips to access the cached tail fields six times per iteration (`OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT` = 4b × 6 = 24b per iteration in altstack plumbing alone).

**The hashOutputs closure (67b vs 30b)** includes a varint-length encoding branch for the null-data append option; pseudo-ASM undercounted this.

### 3.2 Stack-arithmetic corrections relative to pseudo-ASM

**§3.5 tail cache SPLIT semantics (audit §3.1 concern confirmed).** Pseudo-ASM's `<32> OP_SPLIT OP_TOALTSTACK` leaves the _suffix_ on altstack, losing access to the tokenId. Corrected to:

```
<32> OP_SPLIT OP_SWAP OP_TOALTSTACK
```

where the SWAP moves the prefix (tokenId) to the top before TOALTSTACK. This pattern repeats for all 7 tail-field splits (+7b cumulatively vs pseudo's implied direct TOALTSTACK).

**§3.5 also needed an OP_RETURN offset resolver.** The pseudo-ASM placeholder `<OP_RETURN_offset>` is a deployment-time constant (PREFIX + SUFFIX lengths are known once the template is compiled), but the A.1.1 implementation uses a `0000 0000 OP_CAT` placeholder that the SDK's deployer will patch to the real offset. This is ~4b in the real script; future deployment tooling will fix-up this constant post-assembly.

**§3.6 owner identity — explicit CHECKSIGVERIFY added per spec §8.1 / decision #29.** Pseudo-ASM's claim that the covenant CHECKSIGVERIFY doubles as owner-auth is rejected. The PKH branch in A.1.1 does two things: HASH160 match + explicit CHECKSIGVERIFY. This adds 1b (the explicit CHECKSIGVERIFY opcode) vs the rejected pattern. The MPKH branch uses the existing audit-§3.2 breakdown: parse m/n from preimage, unroll × 5 pubkey slot extractions gated on nonzero length, then CHECKMULTISIGVERIFY.

### 3.3 What A.1.1 still papers over

- `owner_field` extraction from the variable prefix inside the body is sketched but not rigorously validated against a real scriptCode layout. The SDK's deployer needs to freeze the variable-prefix parse offsets.
- The path-dispatcher gating (`OP_DUP OP_1 OP_EQUAL OP_IF ... OP_ENDIF`) assumes path 1 branch contains the flex-transfer SUFFIX inline. This is correctly measured. Path 2-4 stubs are `OP_FALSE OP_VERIFY` placeholders — measurable (2b each) but obviously non-functional.
- Stack choreography across sections is best-effort: consumption-production invariants have NOT been formally verified. The script compiles, but has not been executed. Measurement is the load-bearing artifact here; semantic correctness is A.2 work.

---

## 4. Spec gaps discovered (for user review)

### 4.1 `NORMAL_BODY_INLINE` circular dependency

Contract template (spec §9.9) embeds `NORMAL_BODY_INLINE` as a constant, meaning Contract body = PREFIX + SUFFIX + OP_RETURN + tail, where SUFFIX (path 6 issue) must reconstruct Normal outputs using the inlined Normal body. If Contract is deployed before Normal, it must pin a specific Normal body hash; if Normal ever changes, all Contract UTXOs are orphaned.

**Status:** spec §14 mentions "deploy-time hash verification (SDK tool)" which presumably addresses this, but the ordering / versioning rules for template-hash updates are not enumerated. A.2 Contract work will need to close this.

### 4.2 `body_before_tail` offset resolution

The Normal body knows its own scriptCode and needs to isolate `body_before_tail` (= PREFIX + SUFFIX, used by output reconstruction) from the full scriptCode (= variable_prefix + PREFIX + SUFFIX + OP_RETURN + tail). Spec §5 describes the layout but does not specify the offset-walk strategy. Two options:

- **Walk from start:** parse variable_prefix (owner_push + action_data + OP_2DROP) via length-prefix reads, then remaining bytes before `6a` (OP_RETURN) are body_before_tail.
- **Walk from end:** find `6a` from OP_RETURN scan; bytes between the `4c 02 01 ff 75` marker and `6a` are body_before_tail.

A.1.1 uses walk-from-start (tail-cache starts after `4c 02 01 ff 75` marker and walks forward). Neither strategy is mandated by spec. **Gap:** spec §5 should pin the walk direction.

### 4.3 `owner_push` length determination in output reconstruction

When reconstructing output candidates, the Normal body must emit `owner_push ‖ 00 6d ‖ body_before_tail ‖ …`. The owner_push has variable length (21b for PKH: `14` + 20b; 37-172b for MPKH: `4c XX` + MPKH preimage bytes). The output tuple in unlocking pushes the owner bytes raw (without length prefix) so the script must compute and emit the correct push-opcode prefix.

Spec §9.2 output_tuple says "owner 20b or MPKH preimage" but doesn't specify whether the stored bytes include the push prefix or just the raw bytes. A.1.1 assumes raw bytes and constructs the push prefix in-script (14b direct push for 20b PKH, or PUSHDATA1+length for MPKH). **Gap:** spec §9.2 should state "owner field = raw bytes, length-prefix reconstructed in locking script" or equivalent.

### 4.4 Depth saturation opcode path

Spec §9.2 rule 10's depth saturation (`new_depth == min(max_input_depth + 1, 65535)`) requires a conditional OP_MIN or explicit branch. A.1.1's implementation checks `new_depth ≥ 0` and `new_depth ≤ 65535` but does NOT verify the exact saturation formula — that is pushed to an A.2 refinement. **Gap:** this is implementation-level, not spec — flagging for A.2 TODO.

---

## 5. DSTAS owner-sig pattern resolution (audit §2.3)

**Finding (high confidence):** For PKH owners, DSTAS relies **solely** on the covenant's CHECKSIGVERIFY. There is no separate owner-sig verification. The MPKH branch adds a CHECKMULTISIGVERIFY (gated by `OP_SIZE OP_NIP OP_IF`, meaning "if the owner field is a nontrivial MPKH preimage, run multisig"). Grep of `dstas-locking-template.ts` confirms exactly one `OP_CHECKSIGVERIFY` (covenant block) and one `OP_CHECKMULTISIGVERIFY` (MPKH branch).

**Security implication:** DSTAS's OP_PUSH_TX covenant constructs a valid signature algorithmically from `HASH256(preimage)` and asserts CHECKSIGVERIFY against generator-point-derived pubkeys (`038ff83d...` or `023635954789...`). This proves:

- The spender provided a valid preimage for the input.
- The outputs committed by SIGHASH_ALL in that preimage.

It does NOT prove the owner authorized the spend. The constructed-sig pattern is universal — anyone with the preimage (which anyone can construct, given the tx) can satisfy it. The only barrier to spending a PKH DSTAS UTXO is whether the spender can satisfy the **rest of the script** (output reconstruction, tail-match, hashOutputs binding). If those constraints are all satisfiable by an adversary (they typically are, since the adversary controls tx construction), the PKH owner field is **not a security boundary** — it's a constant.

**Status:** this is a potentially material security finding for DSTAS, but it does NOT affect BNTP v2 (decision #29 mandates explicit CHECKSIGVERIFY for PKH owner). Suggest filing as a separate issue/investigation against DSTAS. Verification requires building a test vector: (a) encode a DSTAS UTXO with owner PKH = X's key, (b) construct a spend tx with different outputs as adversary (not holding X's key), (c) check whether the tx is consensus-valid. If yes, the finding is confirmed. If no, the script has an implicit owner-sig check I missed.

**Recommendation:** do NOT block BNTP v2 on DSTAS finding. Proceed with A.2, file DSTAS investigation as a separate task.

---

## 6. Recommendations for A.2 (refresh/freeze/confiscate)

### 6.1 Budget slack

We have **~800b slack** between measured 1901b and PASS ceiling 2600b. A.2 adds three paths:

- Path 2 refresh: audit 320-380b
- Path 3 freeze: audit 280-310b (includes 32b `h_Frozen` embed)
- Path 4 confiscate: audit 210-230b

**Sum: ~810-920b.** Direct sum sits right at the PASS ceiling (2700-2820b), but paths are mutually exclusive in the dispatcher — only the selected path's body executes, and the bytes for all four paths sit in the scriptCode. So the additive cost is the full sum of all path SUFFIXes.

**Projected A.2 total: 2711-2821b** → lands in PIVOT or just above ABORT. This is tight. Recommendations:

- Path 3 freeze SUFFIX is the biggest risk because of the SHA256 hash-check of pushed Frozen body (~40b) plus reconstruction with variable owner_push. Budget path 3 at 310b max.
- Path 2 refresh can save ~50b if null-data parsing reuses patterns from §3.4 preimage parse (factor out a subroutine — but BSV has no jumps, so "factor out" means inlining the same byte sequence twice at 2× cost, or accepting the duplication).
- Path 4 confiscate is the cheapest; no notable risk.

If A.2 projects over 2700b, propose spec amendment to raise G5 to ≤ 2900b or cap feature set (e.g. defer MPKH authority in v2.0, enable in v2.1).

### 6.2 Stack-arithmetic caution

The per-output-reconstruction block in A.1.1 weighs 155b and is the biggest risk area for stack bugs. A.2's refresh path does 2 reconstructions (refreshed + royalty), freeze does 1, confiscate does 1. Across all three A.2 paths that's 4 reconstruction blocks total — if A.1.1's per-block cost generalizes, that's 620b of reconstruction alone, matching path 1's budget. Plan accordingly.

### 6.3 Test infrastructure blocker

`npm test` fails with a pre-existing ts-jest/jest version incompatibility (ts-jest 29.4.6 / jest 30.2.0). See §5 Validation notes below. A.2 should first fix the jest setup (upgrade ts-jest to ^30 or pin jest to ^29) — this is a 5-minute fix but out of A.1.1 scope. Until then, tests must be run via `npx tsx` workaround.

---

## 7. Next action

**Recommended:** proceed to A.2 (refresh/freeze/confiscate path SUFFIXes) with the following gates:

1. **Before A.2 work starts:** fix jest/ts-jest version mismatch so `npm test -- bntp-v2-normal-template-size` runs green. This is blocking for running the test file this PR adds.
2. **Budget target for A.2:** 710-910b additive. Hard ceiling: total body ≤ 2700b.
3. **If A.2 projects > 2700b:** PIVOT with a G5 amendment to ≤ 2900b (still a ~28% reduction vs v1 NormalBase 4054b) OR optimization pass on A.1.1 covenant (50-80b savings via DSTAS §5.1 optimizations).
4. **Side-channel DSTAS investigation:** file separate task to confirm/refute the §5 owner-sig finding. Do not block BNTP v2 on this.

**Alternative (less recommended):** re-visit A.1.1 for stack-correctness validation (formal stack trace across whole body) before proceeding. This would convert A.1.1 from byte-budget falsification to executable-correctness proof. ~2-3h additional work. Only needed if downstream B.1 (SDK builders) hits stack bugs that surface as unlocking-satisfaction failures.

---

## Appendix — Validation run

Script runner blocked by environment (`ts-jest/presets/default-esm not found relative to rootDir` — pre-existing jest/ts-jest version mismatch, reproduced on unrelated `tests/asm-template-builder.test.ts`, NOT introduced by A.1.1). Workaround: ran all test assertions via `npx tsx` inline script. Result:

```
 OK  deterministic length
 OK  deterministic bytes
 OK  marker byte 0 (0x4c)
 OK  marker byte 1 (0x02)
 OK  marker byte 2 (0x01)
 OK  marker byte 3 (0xff)
 OK  marker byte 4 (0x75)
 OK  size <= 2700 (ABORT ceiling)
 OK  size >= 1500 (regression floor)
 OK  section sum == total
 OK  verdict not ABORT

Total: 11 tests. Passed: 11. Failed: 0
NORMAL_BODY_SIZE = 1901
Verdict: PASS
```

Compiled byte-exact is deterministic across independent compile passes. All assertions pass.
