# BNTP v2 — PREFIX stack-contract redesign (Wave D)

**Status:** proposed design, pending sign-off. Supersedes the altstack-centric
PREFIX used in Phase 1A + Phase 1B Wave C.

**Motivation:** five consecutive Wave-C execution-verification waves (C.1-C.5)
each fixed one same-class stack-order bug. Every subsequent wave exposed
another one of the same shape in the next block. The redesign eliminates the
shared root cause so Wave D is a single rewrite, not an indefinite drip of
patches.

---

## 1. What we're doing, and why

### 1.1 Root cause (observed, not inferred)

Phase 1A shipped a byte-measurable, structurally-complete PREFIX but
explicitly flagged (§3.5 comment in `normal-body.ts` as-written in A.1.1):

> several stack-management sequences are best-effort reproductions of the
> pseudo-ASM's intent with audit-flagged stack corrections. The primary
> purpose of A.1.1 is to falsify the byte-budget assumption via concrete
> artifact — NOT to ship a ready-to-deploy covenant. Execution correctness
> is A.2 / Phase 1B work.

Each PREFIX block (`COVENANT_PREIMAGE_ROLL`, `SIGHASH_CHECK`,
`PREIMAGE_PARSE`, `TAIL_CACHE`, `OWNER_IDENTITY`) was written against an
_imagined_ altstack layout. The implied layouts are inconsistent across
blocks: what block A leaves on altstack does not match what block B consumes
from altstack. Compilation is syntactically correct (opcodes are valid,
byte-budget passes) but execution exposes the mismatches one-by-one as the
script walks past each earlier-working block.

Wave-C bug chain, all same class:

| Wave | Block fixed          | Symptom at failing pc                               | Cause (one sentence)                                                             |
| ---- | -------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------- |
| C.1  | covenant preamble    | HASH256 on owner_pubkey                             | block expected preimage on top; unlocking pushes pubkey on top.                  |
| C.2  | sighash check        | preimage consumed by premature SPLIT                | spurious `OP_NIP` between `OP_SIZE` and `OP_4 OP_SUB`.                           |
| C.3  | preimage parse       | "OP_SPLIT out of range" in varint dispatcher        | dispatcher was written against push-opcode encoding, not Bitcoin varint.         |
| C.4  | tail cache           | "OP_SPLIT out of range" in push-opcode dispatcher   | SWAP missing after `OP_1 OP_SPLIT`; and dispatcher imagined wrong serialization. |
| C.5  | owner identity (PKH) | "Bitwise length mismatch" at pc 620                 | 4× `OP_FROMALTSTACK` pulled `amount` (16b); `20 OP_AND` failed on 16b × 1b.      |
| —    | (next, found cold)   | path 1 hashPrevouts bind expects wrong altstack top | `TAIL_CACHE` leaves scriptCode on alt top; binding-bind expects hashPrevouts.    |

The C.5 rewrite also shrank Normal body by 90b (2467 → 2377), not because
C.5 was _needed_ to be small but because the original was bloated by dead
altstack choreography. That's the pattern. The fundamental problem is not
five separate bugs, it's one dysfunction: **there is no shared altstack
contract across PREFIX blocks**.

### 1.2 Why iterative per-block fixes stop working

Altstack is LIFO. There is no `OP_PICK_ALT` and no `OP_ROLL_ALT` — only
`OP_TOALTSTACK` / `OP_FROMALTSTACK`. Any block that needs a specific alt
item must first pop everything above it, rearrange on main, and push back.
That cost is duplicated across every consumer. With 13 items on altstack
(as Wave C.4 produced), every PATH block pays a ~15-round-trip tax and each
round-trip is a point of stack-order regression.

### 1.3 Strategy

Put persistent state on the **main stack** at **fixed compile-time
depths** ("system zone"). Altstack is reserved for transient stashes
within a single PREFIX block (e.g., stash sig+pubkey during owner-prefix
extraction) and is **empty when PREFIX hands off to the dispatcher**.

Paths read state via `OP_N OP_PICK` at known depths — constant-time
random access, no LIFO gymnastics, no cross-block assumptions.

---

## 2. System zone (PREFIX postcondition)

When PREFIX completes, main stack top-down is:

| depth | size   | field          | source                                                                                                                                                                                  |
| ----- | ------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | varies | path_id        | unlocking (scriptnum 1-4)                                                                                                                                                               |
| 1     | 32b    | hashPrevouts   | preimage                                                                                                                                                                                |
| 2     | 36b    | thisOutpoint   | preimage                                                                                                                                                                                |
| 3     | 32b    | hashOutputs    | preimage                                                                                                                                                                                |
| 4     | 20b    | owner_pkh      | scriptCode variable prefix                                                                                                                                                              |
| 5     | varies | body           | scriptCode between action_data and OP_RETURN                                                                                                                                            |
| 6     | varies | optionalData   | scriptCode tail                                                                                                                                                                         |
| 7     | 2b     | depth          | scriptCode tail                                                                                                                                                                         |
| 8     | 20b    | confiscAuth    | scriptCode tail                                                                                                                                                                         |
| 9     | 20b    | freezeAuth     | scriptCode tail                                                                                                                                                                         |
| 10    | 1b     | authFlags      | scriptCode tail                                                                                                                                                                         |
| 11    | 16b    | amount         | scriptCode tail                                                                                                                                                                         |
| 12    | 20b    | issuerPkh      | scriptCode tail                                                                                                                                                                         |
| 13    | 32b    | tokenId        | scriptCode tail                                                                                                                                                                         |
| 14+   | —      | unlocking rest | `funding_outpoint, null_data, max_input_depth, selfPos, outpoints, amounts, tuples..., M` (path 1 scope; other paths have different depth-14+ layouts but same depth-0..13 system zone) |

This layout is what Phase 7's altstack drain + `OP_13 OP_ROLL` produces
natively (see §3.7). It's the canonical zone — all path SUFFIXes must
access state at these exact depths.

**Altstack: empty.**

Notes:

- `path_id` sits on top so the dispatcher's `OP_DUP OP_N OP_EQUAL OP_IF`
  pattern works without explicit PICK. Each path SUFFIX ends with `OP_DROP`
  to consume it.
- `owner_pkh` stays in the zone for path 2 (refresh) which asserts
  `output[0].owner == my_owner`. Paths 1/3/4 don't need it but paying the
  20b slot is cheaper than re-deriving.
- `body` stays in the zone because paths 1, 2, 4 all reconstruct candidate
  output locking scripts that reuse the source's body verbatim.
- Depth-14+ is path-specific. Path 1 keeps the full flex-transfer
  unlocking tail; paths 2/3/4 have their own layouts. The **system zone
  (depths 0-13) is invariant across paths**.

### 2.1 Depth budget

14 items in the zone. Max PICK depth is 13 → fits in `OP_13` (single-byte
opcode). Paths that need to reach into depth-14+ (e.g., path 1 reading
`selfPos` or `M`) use `OP_DEPTH OP_N OP_SUB OP_PICK` as today — those
indices are counted from the bottom of the stack and are stable across
paths because the system zone above them is fixed-size.

---

## 3. PREFIX phases

Seven phases, executed in order. All phases consume ≥0 opcodes and have
well-defined pre/post conditions on both stacks. Phases 1-3 are unchanged
from Wave C.1-C.3 (they're the only blocks known to execute correctly).
Phases 4-7 are rewritten.

### 3.1 Phase 1 — preimage roll (unchanged from Wave C.1)

**Source:** `COVENANT_PREIMAGE_ROLL_ASM` in `shared-prefix.ts`.

- **Pre:** `main = [pubkey, sig, path_id, preimage, ...unlocking_rest]`; `alt = []`.
- **Post:** `main = [preimage_copy, preimage, path_id, sig, pubkey, ...unlocking_rest]`; `alt = []`.
- **Cost:** 3b (`OP_3 OP_ROLL OP_DUP`).

### 3.2 Phase 2 — covenant (unchanged)

**Source:** `COVENANT_S_PREAMBLE_ASM ‖ COVENANT_TAIL_ASM`.

- **Pre:** preimage copy on top (consumed by HASH256), preimage preserved at depth 1.
- **Post:** preimage on top, remaining main stack below unchanged; `alt = []`.
- **Cost:** ~270b (DSTAS donor, unchanged).

### 3.3 Phase 3 — sighash check (unchanged from Wave C.2)

**Source:** `SIGHASH_CHECK_ASM`.

- **Pre:** preimage on top.
- **Post:** preimage on top (preserved), `alt = []`.
- **Cost:** ~11b.

### 3.4 Phase 4 — preimage parse (unchanged from Wave C.3)

**Source:** `PREIMAGE_PARSE_ASM`.

- **Pre:** `main = [preimage, path_id, sig, pubkey, ...unlocking_rest]`; `alt = []`.

  _(Note: after phases 1-3, sig and pubkey are at depths 3 and 4 respectively.
  Phase 1's `OP_3 OP_ROLL OP_DUP` brought preimage to top from depth 3 over
  [pubkey, sig, path_id]. The covenant consumes the DUP'd copy. Phase 3's
  SIGHASH_CHECK leaves preimage on top. Phase 4 consumes the preimage.)_

- **Post:** `main = [path_id, sig, pubkey, ...unlocking_rest]`;
  `alt top-down = [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]`.
- **Cost:** ~35b.

**Wait — actually phase-1 roll order makes sig/pubkey placement different.**

Let's pin this down precisely. The unlocking assembles bottom-to-top:
`[M, tuples..., ..., preimage, path_id, sig, pubkey]` (pubkey pushed last →
on top). So **main top-down = [pubkey, sig, path_id, preimage, ...]**.

`OP_3 OP_ROLL` moves depth-3 item (preimage) to top. Stack becomes
`[preimage, pubkey, sig, path_id, ...unlocking_rest]`. `OP_DUP` →
`[preimage, preimage, pubkey, sig, path_id, ...]`.

Covenant consumes the top preimage (HASH256). After Phase 2: `[preimage,
pubkey, sig, path_id, ...]`. Phase 3 preserves the preimage on top.
Phase 4 consumes preimage and leaves state on altstack. After Phase 4:

`main = [pubkey, sig, path_id, ...unlocking_rest]`
`alt top-down = [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]`

**This is the documented exit state of Phase 4. Phases 5-7 start here.**

### 3.5 Phase 5 — owner prefix + identity check (REWRITE)

Walks the first 23 bytes of scriptCode (`0x14 ‖ owner_pkh(20) ‖ 0x00 0x6D`),
verifies the owner marker, extracts owner_pkh, verifies
`HASH160(pubkey) == owner_pkh`, runs `OP_CHECKSIGVERIFY` against the
preimage authorization.

- **Pre:** `main = [pubkey, sig, path_id, ...rest]`;
  `alt top-down = [scriptCode, hashOutputs, thisOutpoint, hashPrevouts]`.
- **Post:** `main = [rest_of_scriptCode, path_id, ...rest]`;
  `alt top-down = [owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]`.

`rest_of_scriptCode` at this point = `[body ‖ 0x6A ‖ tail]` (the `0x14 ‖
owner_pkh ‖ 0x00 0x6D` prefix has been stripped and verified).

**Implementation (natural OP_SPLIT walk, no altstack items disturbed below
scriptCode):**

```asm
OP_FROMALTSTACK                   ; main: [scriptCode, pubkey, sig, path_id, ...]
OP_1 OP_SPLIT OP_SWAP             ; main: [leadByte, rest_sc, pubkey, sig, ...]
14 OP_EQUALVERIFY                 ; verify marker == 0x14; main: [rest_sc, pubkey, sig, ...]
14 OP_SPLIT OP_SWAP               ; main: [owner_pkh, rest_sc2, pubkey, sig, ...]
OP_DUP OP_TOALTSTACK              ; copy owner_pkh to alt (persistent zone slot)
                                  ; alt top-down: [owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]
OP_3 OP_PICK OP_HASH160           ; main: [hash160(pubkey), owner_pkh, rest_sc2, pubkey, sig, ...]
OP_EQUALVERIFY                    ; main: [rest_sc2, pubkey, sig, ...]
OP_TOALTSTACK                     ; stash rest_sc2 (will be pulled in Phase 6)
                                  ; alt top-down: [rest_sc2, owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]
OP_CHECKSIGVERIFY                 ; pops pubkey (top) then sig; main: [path_id, ...rest]
OP_FROMALTSTACK                   ; main: [rest_sc2, path_id, ...rest]
                                  ; alt top-down: [owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]
OP_2 OP_SPLIT OP_SWAP             ; main: [action_data, rest_sc3, path_id, ...]
006D OP_EQUALVERIFY               ; verify OP_0 OP_2DROP; main: [rest_sc3, path_id, ...]
```

`rest_sc3 = [body ‖ 0x6A ‖ tail]`.

- **Cost:** ~21b.

Scope: PKH owner only. MPKH owner (first byte 0x4C PUSHDATA1) is rejected
by `14 OP_EQUALVERIFY` on the marker byte. MPKH support is a Wave-E/F
follow-up; matches current Wave C.4 scope.

### 3.6 Phase 6 — body extraction + tail walk (REWRITE)

Extracts `body` via compile-time-known `|body|` length split, strips the
`OP_RETURN` marker, then does the **natural forward walk** on the tail
(7 splits, 7 field values built up on main in reverse of their tail order).

- **Pre:** `main = [rest_sc3, path_id, ...rest]` (with `rest_sc3 = body ‖
0x6A ‖ tail`);
  `alt top-down = [owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]`.
- **Post:** `main = [optionalData, depth, confiscAuth, freezeAuth,
authFlags, amount, issuerPkh, tokenId, path_id, ...rest]`;
  `alt top-down = [body, owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]`.

**Implementation:**

```asm
; Extract body (|body| is a compile-time constant, encoded as a fixed-width
; 2-byte LE push so the block's compiled size is invariant in |body|).
${body_len_push}                  ; push |body| as 2-byte value
OP_BIN2NUM                        ; scriptnum form
OP_SPLIT OP_SWAP                  ; main: [body, rest_sc4, path_id, ...]
OP_TOALTSTACK                     ; stash body
                                  ; alt top-down: [body, owner_pkh, hashOutputs, thisOutpoint, hashPrevouts]

; Strip OP_RETURN marker.
OP_1 OP_SPLIT OP_SWAP             ; main: [0x6A, tail, path_id, ...]
6A OP_EQUALVERIFY                 ; main: [tail, path_id, ...]

; Natural forward walk of tail (each SPLIT leaves right-part on top, left-
; part at depth 1, building the system zone top-down exactly as designed).
20 OP_SPLIT                       ; extract tokenId (32b); rest on top
14 OP_SPLIT                       ; extract issuerPkh (20b)
OP_16 OP_SPLIT                    ; extract amount (16b) — OP_16 is single byte
OP_1 OP_SPLIT                     ; extract authFlags (1b)
14 OP_SPLIT                       ; extract freezeAuth (20b)
14 OP_SPLIT                       ; extract confiscAuth (20b)
OP_2 OP_SPLIT                     ; extract depth (2b); optionalData on top
```

After the 7 splits, main top-down is:
`[optionalData, depth, confiscAuth, freezeAuth, authFlags, amount, issuerPkh, tokenId, path_id, ...rest]`.

The split order is chosen so that each field value lands at its designed
zone depth **without any SWAP or ROLL**. This is the key insight: the
OP_SPLIT convention (right-part on top) combined with sequential splits
from the front naturally builds the target layout.

- **Cost:** ~23b (split tail ~18b + body extract ~5b + OP_RETURN strip
  ~3b).

### 3.7 Phase 7 — altstack drain + dispatcher (REWRITE)

Pulls the 5 cached items (`body, owner_pkh, hashOutputs, thisOutpoint,
hashPrevouts`) onto main to complete the system zone, then rolls `path_id`
from depth-13 to the top for the dispatcher.

- **Pre:** see Phase 6 post.
- **Post:** system zone as specified in §2; `alt = []`.

**Implementation:**

```asm
; Pull 5 cached items (altstack becomes empty).
OP_FROMALTSTACK                   ; [body, optionalData, ..., tokenId, path_id, ...]
OP_FROMALTSTACK                   ; [owner_pkh, body, optionalData, ..., tokenId, path_id, ...]
OP_FROMALTSTACK                   ; [hashOutputs, owner_pkh, body, ...]
OP_FROMALTSTACK                   ; [thisOutpoint, hashOutputs, owner_pkh, body, ...]
OP_FROMALTSTACK                   ; [hashPrevouts, thisOutpoint, hashOutputs, owner_pkh, body, ...]

; At this point main top-down is:
;   [hashPrevouts, thisOutpoint, hashOutputs, owner_pkh, body,
;    optionalData, depth, confiscAuth, freezeAuth, authFlags,
;    amount, issuerPkh, tokenId, path_id, ...rest]
;
; We want the system zone (per §2):
;   [path_id, optionalData, depth, confiscAuth, freezeAuth, authFlags,
;    amount, issuerPkh, tokenId, hashPrevouts, thisOutpoint, hashOutputs,
;    owner_pkh, body, ...rest]
;
; The current layout already has the tail fields at depths 5-12 in the
; right order relative to each other, and hashPrevouts/thisOutpoint/
; hashOutputs/owner_pkh/body are at depths 0-4 in reverse of the zone's
; depth 9-13 slots. That means we need to bring path_id (depth 13) to
; top AND leave the rest in place.

OP_13 OP_ROLL                     ; path_id to top; everything else shifts down by 1
                                  ; main: [path_id, hashPrevouts, thisOutpoint, hashOutputs,
                                  ;        owner_pkh, body, optionalData, depth, confiscAuth,
                                  ;        freezeAuth, authFlags, amount, issuerPkh, tokenId, ...rest]
```

The produced layout matches §2 byte-for-byte — this is the canonical zone.
Paths access state via `OP_N OP_PICK` at the depths documented in §2.

**Dispatcher (after zone is built):**

```asm
OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY     ; range check path_id ∈ [1,4]
OP_DUP OP_1 OP_EQUAL OP_IF
  ${PATH1_FLEX_TRANSFER_ASM}
  OP_1                                    ; truthy marker (§3.7 invariant)
OP_ENDIF
OP_DUP OP_2 OP_EQUAL OP_IF
  ${PATH2_REFRESH_ASM}
  OP_1
OP_ENDIF
OP_DUP OP_3 OP_EQUAL OP_IF
  ${PATH3_FREEZE_ASM}
  OP_1
OP_ENDIF
OP_DUP OP_4 OP_EQUAL OP_IF
  ${PATH4_CONFISCATE_ASM}
  OP_1
OP_ENDIF
OP_NIP                                    ; drop path_id, keep OP_1 on top
```

Script succeeds (leaves truthy) iff exactly one path branch completes all
its VERIFY checks. Each branch ends with an explicit `OP_1` push
_inside_ the IF block, so after the dispatcher the main stack top-down
is `[OP_1, path_id, ...system_zone_rest, ...unlocking_rest]`. The final
`OP_NIP` drops `path_id` at depth 1 and leaves `OP_1` on top — the
truthy sentinel the evaluator looks for.

**Invariant (trailing OP_1, decision D.0.4):** every path SUFFIX
consumes all unlocking items it needs (via direct access or OP_DROP),
does NOT drain the system zone, and does NOT push any trailing values
other than the single `OP_1` sentinel emitted by the dispatcher itself.
Paths that need to build per-output intermediates use altstack (per
Altstack rule §5.2: drained before path exit).

- **Cost:** drain ~5b + roll 2b + dispatcher header+middle ~25b = ~32b.

### 3.8 Total PREFIX size estimate (new design)

| Phase                   | Size  | Note                                |
| ----------------------- | ----- | ----------------------------------- |
| 1. Preimage roll        | 3b    | unchanged from Wave C.1             |
| 2. Covenant             | ~270b | unchanged                           |
| 3. Sighash check        | 11b   | unchanged from Wave C.2             |
| 4. Preimage parse       | ~35b  | unchanged from Wave C.3             |
| 5. Owner prefix + check | ~21b  | **replaces Wave C.4 + C.5 (~144b)** |
| 6. Body + tail walk     | ~23b  | **replaces Wave C.4 tail walk**     |
| 7. Drain + dispatcher   | ~32b  | dispatcher ~unchanged, drain is new |
| **Total PREFIX**        | ~395b | **vs current ~475b**                |

Estimated savings: ~80b on PREFIX. Normal body target: ~2300b (from
current 2377b). Not the primary goal — correctness is — but a useful
secondary metric.

---

## 4. Path access patterns

All paths read zone state via `OP_N OP_PICK` (constant time, constant
depth). Examples using the reconciled §3.7 zone:

### Path 1 (flex-transfer) highlights

- `hashPrevouts` (for binding check against `HASH256(outpoints ‖
funding_outpoint)`): `OP_1 OP_PICK` (depth 1).
- `thisOutpoint` (for selfPos check): `OP_2 OP_PICK`.
- `my_amount` (for conservation check): `OP_11 OP_PICK`.
- `my_depth` (for max_input_depth check): `OP_7 OP_PICK`.
- `hashOutputs` (for closure): `OP_3 OP_PICK`.
- `body` (for candidate output reconstruction): `OP_5 OP_PICK` (used in
  inner output-construction loop; PICK inside a loop reads the same slot
  each iteration because the loop only grows _above_ the zone).
- `tokenId, issuerPkh, authFlags, freezeAuth, confiscAuth, optionalData`
  (for tail reconstruction): PICKs at depths 13, 12, 10, 9, 8, 6
  respectively.

### Path 2 (refresh)

- `owner_pkh` (for `output[0].owner == my_owner` invariant): `OP_4 OP_PICK`.
- `issuerPkh` (for royalty output owner and MPKH issuer identity):
  `OP_12 OP_PICK`.

### Path 3 (freeze)

- `freezeAuth` (for authority identity check): `OP_9 OP_PICK`.
- `authFlags` (for PKH-vs-MPKH discrimination): `OP_10 OP_PICK`.

### Path 4 (confiscate)

- `confiscAuth`: `OP_8 OP_PICK`.
- `my_depth` (confiscate **preserves** depth per decision #39):
  `OP_7 OP_PICK`.

### Shared output-reconstruction helper

A.2.5 extracted `VARINT_SERIALIZE_ASM`. Wave D can go further: paths 1, 2,
4 all build a candidate Normal output script `[0x14 ‖ new_owner ‖ 0x00
0x6D ‖ body ‖ 0x6A ‖ reconstructed_tail]`. With the zone in place, a
single `RECONSTRUCT_NORMAL_OUTPUT_ASM(new_owner, new_amount, new_depth)`
helper can replace `PATH1_OUTPUT_ONE_ASM`, `PATH2_OUTPUT_ONE_ASM`, and
path 4's inline reconstruction. Estimated additional savings: ~100b
across paths. **Scope decision: defer to Wave D.2 after D.1 lands and
exercises the zone contract under execution.**

---

## 5. Altstack usage rules (invariants)

1. **Altstack is empty at dispatcher time.** No path SUFFIX may rely on
   altstack carrying PREFIX state — everything persistent is in the main
   zone.
2. **Altstack is empty at path exit.** Each path SUFFIX that uses
   altstack for transient accumulation (e.g., running amount sum in
   path 1) MUST drain it before the path's closing OP_ENDIF.
3. **Intra-phase altstack scope is private.** Any push to altstack
   within a PREFIX phase MUST be popped before the phase's end. The
   only exception is Phase 5 stashing `owner_pkh` and Phase 6 stashing
   `body` — those are explicit hand-offs to Phase 7's drain.

Violations of rule 1 or 2 are classed as correctness bugs (not
optimizations). Violations of rule 3 are classed as spec drift and must
be caught in code review, not execution.

---

## 6. Natural OP_SPLIT walk (reference)

This is the key technique that makes the rewrite simple.

**Observation:** `X N OP_SPLIT` produces `[x2, x1]` with `x2` (right
part, bytes from N onward) on top and `x1` (left part, first N bytes)
at depth 1. Sequential splits on the **top** (i.e. on the successive
right-parts) extract fields **left-to-right** from the source, and
each extracted field is **pushed under the current top**.

For a source with layout `[f_0 | f_1 | f_2 | ... | f_n]`:

```
stack: [source]
push size(f_0); OP_SPLIT  → [rest_0, f_0]      (f_0 at depth 1)
push size(f_1); OP_SPLIT  → [rest_1, f_1, f_0] (f_1 at depth 1, f_0 at depth 2)
...
push size(f_{n-1}); OP_SPLIT → [f_n, f_{n-1}, ..., f_1, f_0]
```

End state top-down: `[f_n, f_{n-1}, ..., f_1, f_0]` — source fields in
**reverse order**. No SWAPs, no altstack.

**Applied to tail walk (Phase 6):**

tail = `[tokenId(32) | issuerPkh(20) | amount(16) | authFlags(1) |
freezeAuth(20) | confiscAuth(20) | depth(2) | optionalData(var)]`

```
20 SPLIT  → [rest, tokenId]
14 SPLIT  → [rest, issuerPkh, tokenId]
16 SPLIT  → [rest, amount, issuerPkh, tokenId]
1  SPLIT  → [rest, authFlags, amount, issuerPkh, tokenId]
14 SPLIT  → [rest, freezeAuth, authFlags, amount, issuerPkh, tokenId]
14 SPLIT  → [rest, confiscAuth, freezeAuth, authFlags, amount, issuerPkh, tokenId]
2  SPLIT  → [optionalData, depth, confiscAuth, freezeAuth, authFlags, amount, issuerPkh, tokenId]
```

That's the target zone layout for slots 5-13 (reconciled §3.7 table),
produced by 7 opcodes without a single SWAP or altstack round-trip.

---

## 7. Scope limits and deferred work

### 7.1 In Wave D

- **PKH owner only.** MPKH owner rejected by marker check in Phase 5.
- **PKH authority (freeze/confisc/issuer) + MPKH authority.** Retained
  from A.2; `authorityIdentityAsm` ported unchanged.
- **Normal template only.** Contract and Frozen migrations are Wave D.5
  (mechanical port of the same PREFIX contract).

### 7.2 Deferred to later waves

- MPKH owner (Wave E or F): requires widened Phase-5 marker dispatch and
  an MPKH-specific `scriptCode` layout acknowledgement in the owner
  prefix walk.
- Shared output-reconstruction helper (Wave D.2 decision): estimated
  ~100b savings, but introduces coupling across paths. Land D.1 first,
  then decide.
- PREFIX further shrinking (covenant preamble optimizations — decisions
  noted but deferred in A.3): separate wave, not in D.

---

## 8. Verification plan

### 8.1 Wave D.1 execution test

The existing `tests/bntp-v2-normal-execution.test.ts` runs the flex-
transfer scenario against the assembled locking+unlocking pair. Currently
in **always-pass diagnostic mode**: logs the trace, the top-of-stack, and
any evaluator error, but does not fail the test.

Wave D.1 acceptance criterion:

> Execution trace reports `success=true`, final `stack=[OP_1]`, no evaluator
> error. Promote the test from diagnostic to strict (`expect(result.success)
.toBe(true)`).

If the trace fails at some pc, the failing opcode must be traceable to
**exactly one** phase of this spec. If it's not — if the failure straddles
phases — this spec has a gap; return to design before patching.

### 8.2 Unit tests for new PREFIX blocks

For each of Phase 5 / 6 / 7, write a micro-test that feeds a synthetic
stack matching the phase's pre-condition and asserts the post-condition
byte-exactly. These tests catch stack-contract drift in isolation, which
the end-to-end execution test doesn't.

Location: `tests/bntp-v2-prefix-phase{5,6,7}.test.ts`. Fixture helper in
`src/bntp/v2/test-helpers.ts`.

### 8.3 Size test

The existing `tests/bntp-v2-normal-template-size.test.ts` should still
pass (body should shrink, not grow). No new assertions needed — the
existing PASS/PIVOT/ABORT gate bands are the acceptance.

### 8.4 Path-specific execution tests

Before Wave D.2/D.3 (rewriting paths 2/3/4), extend the execution test
with `path=refresh`, `path=freeze`, `path=confiscate` scenarios. Each
must succeed with the new zone-based paths.

---

## 9. Implementation plan

| Wave | Scope                                                 | Acceptance                                          |
| ---- | ----------------------------------------------------- | --------------------------------------------------- |
| D.0  | This design doc + sign-off                            | user approval                                       |
| D.1  | Rewrite phases 5-7 in `shared-prefix.ts` + dispatcher | flex-transfer execution test: strict `success=true` |
| D.2  | Rewrite path 1 SUFFIX using PICK-based zone access    | no regression; Normal size ≤ 2400b                  |
| D.3  | Rewrite paths 2/3/4 SUFFIXes using zone               | path-specific execution tests pass strict           |
| D.4  | Promote path 2/3/4 execution tests from diagnostic    | all paths strict-green                              |
| D.5  | Migrate Contract + Frozen templates to new PREFIX     | existing size tests pass; Contract ≤ 4100b          |

Wave D.1 is the critical milestone: if the flex-transfer test goes
strict-green, the zone contract is correct and D.2-D.5 are mechanical
refactors. If D.1 fails, we learn where the spec is wrong before
committing to 4 more waves.

---

## 10. Decision log

- **Why main-stack-centric, not altstack-centric?** Altstack is LIFO
  without PICK/ROLL. Persistent state with random access requires main
  stack. Period.
- **Why path_id on top instead of deep?** Dispatcher's `OP_DUP OP_N
OP_EQUAL OP_IF` pattern is byte-minimal when path_id is on top. Moving
  it deep would cost 2b × 4 branches = 8b for PICKs inside the
  dispatcher. Also: path_id is **consumed** by the dispatcher's trailing
  OP_DROP, so it's naturally transient — belongs on top.
- **Why keep `body` in the zone, not re-derive?** Paths 1/2/4 all read
  it during per-output reconstruction. Re-deriving would mean re-pulling
  and re-splitting scriptCode each iteration. 100+b per path.
- **Why §3.7 reconciled zone order differs from §2 table?** §2 was
  written top-down as an idealized "natural" reading; §3.7 is what the
  implementation actually produces without introducing extra ROLLs. When
  the two conflict, **§3.7 is authoritative**. The §2 table will be
  updated to match §3.7 in a follow-up edit once D.1 lands.
- **Why not shrink PREFIX further (e.g., fold covenant)?** Out of scope
  for Wave D. Correctness first; optimization later.

---

## 11. Decisions ratified (D.0 sign-off)

Ratified in D.0 review. All four recorded below; spec frozen at
revision 1.

1. **D.0.1 — Zone order.** Adopt the Phase-7-native layout (§2 table,
   reconciled to match §3.7 implementation). Canonical.
2. **D.0.2 — Shared output-reconstruction helper.** Deferred. Wave D.1
   rewrites path 1 inline using PICK-based zone access. A shared
   `RECONSTRUCT_NORMAL_OUTPUT_ASM` helper is a post-D.1 consolidation
   opportunity; re-evaluate after D.1 is strict-green.
3. **D.0.3 — MPKH owner scope.** Wave D ships PKH-only. Phase-5 marker
   check `14 OP_EQUALVERIFY` hard-rejects MPKH owners. MPKH-owner
   support is a separate follow-up wave (E or F) that requires widening
   the Phase-5 marker dispatcher and updating Phase-5's `scriptCode`
   prefix walk.
4. **D.0.4 — Trailing `OP_1` in path branches.** Each path SUFFIX
   branch emits an explicit `OP_1` before its closing `OP_ENDIF`; the
   dispatcher's final `OP_NIP` drops `path_id` and leaves `OP_1` on
   top. Cost +5b total (4b for the four OP_1 pushes, +1b for OP_NIP
   vs OP_DROP). Safety vs relying on "accidentally truthy" zone field
   at top.

Implementation (Wave D.1) may begin.
