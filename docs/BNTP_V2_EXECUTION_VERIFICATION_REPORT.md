# BNTP v2 — Execution Verification Report (Phase 1B Wave C)

**Date:** 2026-04-18
**Template under test:** `src/bntp/v2/templates/normal-body.ts` (2620 b compiled body)
**Evaluator under test:** `src/script/eval/script-evaluator.ts`
**Path exercised:** Normal path 1 — flex-transfer, 1 input → 1 output, PKH owner, `amount=100` preserved, `max_input_depth=0`, `new_depth=1`, no MPKH, no funding input, no null-data, no optionalData.
**Test file:** `tests/bntp-v2-normal-execution.test.ts`
**Helpers file:** `src/bntp/v2/test-helpers.ts`

---

## 1. Verdict

**Outcome B — Execution fails at a specific opcode, early in the covenant.**

The BNTP v2 Normal locking script fails at the OP_CHECKSIGVERIFY that terminates the OP_PUSH_TX covenant (spec §3.2 covenant tail). The failure is deterministic and reproducible; the keypair, preimage construction, and evaluator plumbing all pass an independent P2PK sanity round-trip on the same tx context. The bug is in the template's stack choreography at the very entrance to the covenant, not in the covenant math itself.

---

## 2. How to reproduce

```bash
NODE_OPTIONS='--experimental-vm-modules' npx jest tests/bntp-v2-normal-execution.test.ts
```

Four tests execute; three pass outright (size gate, preimage signability, and a P2PK sanity round-trip with the same keypair), and the last — `flex-transfer execute: unlocking ‖ locking script evaluation` — runs the full stack through the evaluator and reports a `{ success: false, error: "OP_CHECKSIGVERIFY failed" }` verdict as its observed outcome.

## 3. Test construction

### 3.1 Scenario (hard-coded)

| Field                    | Value                                              |
| ------------------------ | -------------------------------------------------- |
| owner private key        | `0x00…0042` (32 bytes; fixed test fixture)         |
| owner PKH                | `HASH160(pubkey)`                                  |
| token amount             | `100` (uint128 LE, preserved input → output)       |
| tokenId                  | 32 zero bytes                                      |
| issuerPkh                | `0x1111…11` (20 bytes)                             |
| authorityFlags           | `0x00` (not freezable, not confiscatable, no MPKH) |
| freezeAuthHash           | 20 zero bytes                                      |
| confiscAuthHash          | 20 zero bytes                                      |
| optionalData             | empty                                              |
| input attestation depth  | `0`                                                |
| output attestation depth | `max_input_depth + 1 = 1`                          |
| input outpoint           | `0xAA…AA:0`                                        |
| satoshis                 | `1` (anti-dust)                                    |
| version / locktime       | `1` / `0`                                          |
| sequence                 | `0xFFFFFFFF`                                       |

### 3.2 Locking-script size

```
variable_prefix (21 owner-push + 1 OP_0 + 1 OP_2DROP)   =   23 b
NORMAL_BODY_BYTES (includes 5-byte body marker)         = 2620 b
OP_RETURN                                               =    1 b
tail (111 fixed + 0 optionalData)                       =  111 b
                                                        ------
                                                        = 2755 b   ✓ matches spec §11.2 / task spec
```

### 3.3 Unlocking stack (pushed, bottom → top)

Per spec §9.2 the flex-transfer unlocking pushes (top element is last):

```
M (OP_1)
output_tuple_0 = amount16 ‖ owner20 ‖ newDepth2 ‖ marker2 = 40 b
amounts_in_array = amount16 (N=1)
all_input_outpoints = 36 b (N=1)
selfPosition (OP_0)
max_input_depth (2 b LE = 0x0000)
null-data (empty push)
funding_outpoint (empty push — no funding input, §9.2 Step C Moderate #7)
preimage (2914 b for this 2755-b scriptCode)
OP_1 (path_id = 1)
owner_sig_with_type (71 b DER + 0x41 byte)
owner_pubkey (33 b compressed)
```

### 3.4 Preimage

Built via the SIGHASH_FORKID BIP143-like layout used by the SDK's own
`src/script/eval/script-evaluator.ts → buildSighashPreimage`:

```
version(4) ‖ hashPrevouts(32) ‖ hashSequence(32) ‖ outpoint(36)
‖ varint(scriptCodeLen) ‖ scriptCode(2755)
‖ satoshis(8) ‖ sequence(4) ‖ hashOutputs(32) ‖ locktime(4) ‖ sighashType(4 = 0x41000000)
= 2914 b
```

Independent sanity: a mini P2PK locking with the same keypair + same ctx evaluates cleanly through the evaluator (`{ success: true }`), confirming the keypair, preimage formula, and evaluator sighash pathway are consistent.

---

## 4. Failure point

### 4.1 Opcode (bytecode-level)

Evaluator trace shows:

| locking-pc | opcode                     | stack top at exec                                     |
| ---------: | -------------------------- | ----------------------------------------------------- |
|         21 | `OP_0` (0x00)              | `…` (stack depth 14)                                  |
|         22 | `OP_2DROP` (0x6d)          | owner_pubkey `03079264c4b4bfcd7fe3a7b7b92b6c43…`      |
|         27 | `OP_DROP` (0x75)           | owner_pubkey `03079264…`                              |
|         28 | `OP_HASH256` (0xaa)        | **← hashes the owner_pubkey, not the preimage**       |
|         29 | `OP_16` (0x60)             | …                                                     |
|        ... | (covenant preamble runs)   |
|        388 | `OP_CAT` (0x7e)            | `…` sig-assembly in progress                          |
|        392 | `OP_CAT` (0x7e)            | final sig `3044022079be…`                             |
|        393 | `OP_SWAP` (0x7c)           |                                                       |
|        394 | `OP_NOTIF` (0x64)          | parity branch — `true` taken, pushes `038ff8…` pubkey |
|        429 | `OP_ELSE` (0x67)           | (skipped)                                             |
|        432 | `OP_CHECKSIGVERIFY` (0xad) | **FAILS** — `OP_CHECKSIGVERIFY failed`                |

The covenant's fixed-R signature construction produces an `s` value that is only valid against `HASH256(pushed_preimage)`. The evaluator, when executing CHECKSIGVERIFY, independently rebuilds the BIP143-like preimage from `ctx.tx + scriptCode + sighashType=0x41` and hashes **that**. For the covenant to succeed, the input to OP_HASH256 at pc=28 must be the preimage bytes the evaluator will reconstruct.

In this run, OP_HASH256 instead hashed the 33-byte compressed `owner_pubkey`. The covenant then builds a sig valid against `HASH256(owner_pubkey)`, not `HASH256(preimage)`, so CHECKSIGVERIFY rejects it.

### 4.2 Why the wrong value is on top of stack

After the variable prefix (`OP_2DROP` at pc=22) and body marker (`OP_DROP` at pc=27), the BNTP v2 Normal body enters `COVENANT_S_PREAMBLE_ASM`, which begins immediately with `OP_HASH256` (see `src/bntp/v2/templates/shared-prefix.ts` line 36 — first real opcode of the block). The covenant therefore **requires** the preimage to be on top of the main stack at that moment.

But per spec §9.1 / §9.2 (and implemented by `buildFlexTransferUnlocking` in `test-helpers.ts`), the unlocking pushes in this order (top is pushed last):

```
... preimage, path_id, owner_sig, owner_pubkey   ← top
```

So on entry to the covenant, the top of the stack is `owner_pubkey` (33 b), with `owner_sig` below, `path_id` below that, and `preimage` at depth 3. The `OP_2DROP` in the variable prefix only clears the PKH and action-data pushes that the locker itself placed — it does **not** reorder the unlocking stack.

The covenant has no shim to move preimage to the top of the stack before OP_HASH256. This contradicts the unlocking layout the spec mandates.

### 4.3 Template rule violated

- Spec §9.1 (generic layout):
  ```
  … [preimage] [path_id: 1..6] [sig] [pubKey]
  ```
- Spec §9.2 (flex-transfer): confirms the same ordering, with the pubkey/sig pair appearing last.
- `src/bntp/v2/templates/normal-body.ts` NORMAL_BODY_ASM (lines 802-821) inlines `COVENANT_S_PREAMBLE_ASM` directly after the body marker with no stack adjustment. The covenant itself is a verbatim port of the DSTAS donor, but the surrounding choreography differs (DSTAS runs `OP_DUP OP_2 OP_ADD OP_ROLL OP_DUP OP_HASH256` — explicit rolling of the preimage onto the top — before OP_HASH256; see `src/script/templates/dstas-locking-template.ts`).

The author's own annotation in `normal-body.ts` lines 51-57 flagged the risk: _"several stack-management sequences are best-effort reproductions of the pseudo-ASM's intent… primary purpose of A.1.1 is to falsify the byte-budget assumption via concrete artifact — NOT to ship a ready-to-deploy covenant. Execution correctness is A.2 / Phase 1B work."_ This is that Phase 1B execution-correctness finding.

---

## 5. Where the fix must live (NOT applied here)

`src/bntp/v2/templates/normal-body.ts` — immediately before `${COVENANT_S_PREAMBLE_ASM}` in the `NORMAL_BODY_ASM` template literal. The fix is a 3-opcode shim that rolls the preimage to the top of stack:

```asm
OP_3 OP_ROLL        ; preimage is at depth 3 (under pubkey, sig, path_id) → bring to top
```

or equivalent DSTAS-style `OP_DUP OP_2 OP_ADD OP_ROLL` if the preimage needs to remain available later (DSTAS duplicates before rolling so the preimage is both on-top for the covenant and still underneath for later PREIMAGE_PARSE_ASM).

**Budget impact:** 1 byte for `OP_3 OP_ROLL` (2 b), or 4 b for the DSTAS-style dup+roll. The Normal body at 2620 b has 80 b margin under the 2700 b ABORT ceiling (per `BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md`), so absorbing a 2-4 b shim is safe.

**Ripple effect:** every other template (`frozen-body.ts`, `contract-body.ts`) shares the same `COVENANT_S_PREAMBLE_ASM` and `shared-prefix.ts` source; all three are equally exposed to this bug. Wave D work should either patch each body independently or add the shim to `shared-prefix.ts` (where the covenant helpers live) behind a named export.

Out of scope for Wave C per the task brief: "If you find a bug, DOCUMENT it; do NOT fix."

---

## 6. What was validated

| Check                                                                | Status |
| -------------------------------------------------------------------- | ------ |
| Locking script size matches spec §11.2 / task spec (2755 b)          | ✓      |
| Variable prefix / body / OP_RETURN / tail structure assembles clean  | ✓      |
| Owner key can sign `HASH256(preimage)` and the sig verifies          | ✓      |
| Minimal P2PK locking with same keypair + ctx passes evaluator        | ✓      |
| BNTP v2 Normal locking executes the covenant without stack underflow | ✓      |
| BNTP v2 Normal locking passes OP_CHECKSIGVERIFY at covenant tail     | **✗**  |
| (never reached) sighash-type check, preimage parse, tail cache, etc. | n/a    |

---

## 7. Evaluator observations (not limitations — everything worked)

`src/script/eval/script-evaluator.ts` supports every opcode BNTP v2 uses on this path:

- `OP_CAT`, `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM` (monolith)
- `OP_MUL`, `OP_DIV`, `OP_MOD` (magnetic — needed for `s`-derivation in covenant preamble)
- `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR` (bitwise monolith)
- `OP_CHECKSIGVERIFY` with SIGHASH_FORKID (fails deterministically with a clear error)
- `OP_HASH256`, `OP_HASH160`, `OP_SHA256`, `OP_RIPEMD160`

Script flags passed: `SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_ENABLE_MAGNETIC_OPCODES | SCRIPT_ENABLE_MONOLITH_OPCODES`.
Strict mode disabled (BNTP v2 scripts exceed strict's 10 000-byte `maxScriptSizeBytes`; Phase 1B exercises consensus-level semantics, not pool policy).

The evaluator is entirely capable of executing BNTP v2 scripts. No Outcome C limitation surfaced.

---

## 8. Recommendations for the next Wave C rounds

1. **Fix and re-run the present scenario.** Apply the 2-4 byte covenant-entry shim in `normal-body.ts` (or `shared-prefix.ts`) and re-run this test. The expected next failure (if any) is in `SIGHASH_CHECK_ASM` or `PREIMAGE_PARSE_ASM`, since those also assume specific stack state. The per-round cycle time is seconds; iterate aggressively.
2. **Extend coverage after covenant succeeds.** Obvious next executions, in ascending complexity:
   - N=1, M=4 split.
   - N=4, M=1 consolidate (tests SUM_INPUTS unrolled loop gating on `i < N`).
   - `max_input_depth=42` with `new_depth=43` (tests DEPTH_CHECK).
   - Non-trivial `tokenId`, non-trivial `optionalData` (tests TAIL_CACHE under non-zero lengths and the byte-exact tail match in output reconstruction).
   - `authorityFlags=0x20` MPKH owner (tests OWNER_IDENTITY MPKH branch).
3. **Fuzz the unlocking.** Once happy paths land, adversarial inputs (over-reported `max_input_depth`, wrong `selfPosition`, amount-conservation violations, tampered `hashOutputs`) should deterministically fail at the specific rule the spec §9.2 numbered list predicts.
4. **Re-verify Contract and Frozen templates.** Both inherit `COVENANT_S_PREAMBLE_ASM` from `shared-prefix.ts`; both therefore share this covenant-entry stack bug. Wave C should open parallel execution tests for Frozen path 3 and Contract path 6 once Normal path 1 clears.
5. **Separate evaluator-vs-consensus semantics.** The current evaluator's `buildSighashPreimage` is our BNTP v2 reference; when Wave D SDK builders ship, also cross-check against at least one external implementation (e.g., `bsv-sdk` or a node regtest) to catch any BSV-consensus edge case the local evaluator misses (e.g., minimal-pushdata enforcement, DER-signature strictness).

---

## 9. Deliverables

- `tests/bntp-v2-normal-execution.test.ts` — four tests:
  - size gate (2755 b);
  - preimage-signability sanity;
  - P2PK-same-ctx sanity (keypair + sighash plumbing);
  - flex-transfer full execution verdict (observed `OP_CHECKSIGVERIFY failed`).
- `src/bntp/v2/test-helpers.ts` — reusable builders for:
  - tail construction (`buildTail`);
  - full locking script (`buildNormalLockingScript`);
  - BIP143-like preimage (`buildPreimage`);
  - flex-transfer unlocking stack (`buildFlexTransferUnlocking`);
  - end-to-end scenario assembly (`assembleFlexTransferScenario`).
- This report.

All three deliverables confine themselves to owned scope; no template body, no evaluator, and no spec file was modified.
