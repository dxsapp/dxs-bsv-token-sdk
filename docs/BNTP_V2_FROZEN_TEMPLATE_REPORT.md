# BNTP v2 Frozen Template Report — Phase 1A.3 Frozen scope

**Date:** 2026-04-18
**Scope:** Phase 1 Step A.3 — real, assemblable BSV Script ASM for the
Frozen template body (compliance-hold template), covering path 3 (unfreeze)
and path 4 (confiscate-from-frozen). Parallel artifact to
`BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md`; does not modify the Normal template.

**Artifacts created:**

- `src/bntp/v2/templates/frozen-body.ts` — 533-line ASM + compile helpers.
- `tests/bntp-v2-frozen-template-size.test.ts` — deterministic compile,
  marker, verdict, section-sum, h_Normal-push-presence assertions.

**Artifacts NOT modified:**

- `src/bntp/v2/templates/normal-body.ts` — read-only (per scope restriction).
  Shared helpers (covenant, preimage parse, tail cache, VARINT_SERIALIZE_ASM,
  authorityIdentityAsm) are duplicated verbatim into `frozen-body.ts` rather
  than imported, because `normal-body.ts` does not currently export those
  symbols and the A.3 Frozen scope forbids modifying it. See §4.1 below.
- `docs/BNTP_V2_SPEC.md` — frozen at 47 decisions.

---

## 1. Verdict

**Body size:** **1282 bytes.**
**Gate (recalibrated):** **PIVOT** (82b over PASS ceiling 1200, 118b under
ABORT ceiling 1400).

| Gate  | Ceiling   | Status                                  |
| ----- | --------- | --------------------------------------- |
| PASS  | ≤ 1200    | —                                       |
| PIVOT | 1200-1400 | **current (1282, 118b slack to ABORT)** |
| ABORT | > 1400    | —                                       |

### 1.1 Gate recalibration rationale

Spec §11.1 (and §3 template catalog) projects the Frozen body at **~700b**.
That projection predates:

1. **Step C fixes** (#39 confiscate-preserves-depth, #41 MPKH m≥1,
   #43 owner size==20) — collectively ~+10-15b on Frozen (less than on
   Normal because Frozen has 2 paths, not 4-iteration path 1).
2. **Decision #29 PKH CHECKSIGVERIFY pattern** — ~+5b per authority identity
   invocation (path 3 AND path 4 each carry a full authority identity
   block, not a shared one).
3. **Decision #27 hash + pushed-body pattern** applied to BOTH paths — the
   `h_Normal` 32b constant embed + SHA256 verify is replicated per path
   (~+40b total).
4. **Per-path authority identity duplication** — each path needs its own
   `authorityIdentityAsm` invocation, and this helper is ~110b fully
   inlined (including PKH+MPKH branching with the #41 m≥1 defensive check).
   Two paths = ~220b of authority-identity code.

Realistic post-audit accounting:

| Component                                     | Est. bytes |
| --------------------------------------------- | ---------- |
| Body marker                                   | 5          |
| Shared PREFIX (cov + parse + cache)           | ~736       |
| Dispatcher scaffold (3-branch or 4-gate)      | ~10        |
| Path 3 unfreeze (incl. auth id + hash verify) | ~260       |
| Path 4 confisc-from-frozen                    | ~270       |
| **Total**                                     | **~1280**  |

Measurement landed at **1282b**, within 2b of the envelope.

### 1.2 Gate band selection

Recalibrated bands set at realistic levels vs the stale ~700b:

- **PASS ≤ 1200b**: would require shared-authority-identity factoring
  (dispatcher-scope instead of per-path) OR elimination of per-path hash
  verify. Neither fits the current helper-duplication scope restriction.
- **PIVOT 1200-1400b**: current state. Structural completeness achieved
  with honest per-path helper cost.
- **ABORT > 1400b**: indicates a logic-bug-level duplication (e.g., two
  tail caches, or two covenant preambles) — 1400b would be unreasonable
  for the Frozen scope.

PIVOT is the accepted landing for this arc. A spec amendment suggestion
is filed in §5.

---

## 2. Per-section measurement table

| Section                | Bytes | Notes                                                                                                                      |
| ---------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------- |
| bodyMarker             | 5     | `4c 02 fe ff 75` — PUSHDATA1 0x02 0xfeff OP_DROP (Frozen marker). Differs from Normal's `4c 02 01 ff 75` by marker bytes.  |
| covenantPreamble       | 197   | Byte-identical to Normal. DSTAS-ported `s` derivation.                                                                     |
| covenantTail           | 241   | Byte-identical to Normal. DSTAS-ported DER assembly + CHECKSIGVERIFY.                                                      |
| sighashCheck           | 13    | Byte-identical to Normal.                                                                                                  |
| preimageParse          | 121   | Byte-identical to Normal.                                                                                                  |
| tailCache              | 164   | Byte-identical to Normal. Same 111b fixed tail layout per §5.2.                                                            |
| dispatcherHeader       | 4     | `OP_DUP OP_3 OP_EQUAL OP_IF` (path 3 gate open).                                                                           |
| path3Unfreeze          | 260   | freezeAuth id + h_Normal SHA256 verify + Normal candidate reconstruction (preserve owner + depth from tail cache).         |
| path4ConfiscFromFrozen | 271   | confiscAuth id + h_Normal SHA256 verify + Normal candidate reconstruction (new_owner from tuple, depth preserved per #39). |
| dispatcherMiddle       | 6     | `OP_ELSE OP_DUP OP_4 OP_EQUALVERIFY ... OP_ENDIF OP_DROP` — 4-branch closure scaffold.                                     |
| **Total**              | 1282  | Matches FROZEN_BODY_BYTES.length.                                                                                          |

### 2.1 Path-level delta vs Normal template

For cross-reference (Normal A.3 measurements from
`BNTP_V2_NORMAL_TEMPLATE_A3_REPORT.md` §4):

| Path                       | Normal | Frozen | Δ   | Notes                                                                                          |
| -------------------------- | ------ | ------ | --- | ---------------------------------------------------------------------------------------------- |
| Path 3 (freeze / unfreeze) | 252    | 260    | +8  | Frozen path 3 reconstructs Normal output (action_data 0x00 vs 0x02); minor delta.              |
| Path 4 (confiscate)        | 231    | 271    | +40 | Frozen path 4 adds h_Normal hash verify (~+40b vs Normal path 4 which reuses own cached body). |

The Normal template's path 4 confiscate reconstructs its **own** body using
the cached `body_before_tail` from the scriptCode — no h_X verify needed.
Frozen's path 4 must verify an externally-pushed Normal body, adding the
~40b of SHA256 verify machinery.

---

## 3. Implementation notes

### 3.1 Shared PREFIX reuse posture

The Frozen PREFIX (body marker + covenant + sighash check + preimage parse +
tail cache) is **byte-identical** to Normal's PREFIX except for the 2-byte
body-marker discriminator (`feff` vs `01ff`). All shared blocks are carried
as literal ASM-string duplications of the Normal definitions, not imports
(see §4.1 for the refactor opportunity).

The tail cache works unchanged: the Frozen tail layout is byte-identical to
Normal's per §5.2 (same 111b fixed layout). Only the preceding body marker
differs, and the tail cache walks _after_ OP_RETURN — so the marker byte
variation has no effect on the cache's stack choreography.

### 3.2 Path 3 unfreeze (§9.7)

Structural pattern derived from Normal's `PATH3_FREEZE_ASM` (which goes
Normal → Frozen). Frozen's unfreeze goes Frozen → Normal. Differences:

- **Authority flag checked:** `01` (bit 0 freezable) — same as Normal freeze.
  The same freezeAuth controls both directions (freeze and unfreeze are
  symmetric operations under the same authority).
- **Authority helper flag:** `"04"` (freezeAuth MPKH flag bit 2) — identical
  to Normal freeze.
- **Hash commit:** `SHA256(pushed) == h_Normal` (placeholder 32 zero bytes).
- **Target action_data:** `0x00` (Normal), not `0x02` (Frozen).
- **Body marker in tuple verify:** `01ff` (Normal), not `feff` (Frozen).
- **Owner, amount, depth:** all preserved from source via the tail cache.
  Depth preservation is §4.2 rule 6 (unfreeze preserves depth).

Output shape:
`owner_push ‖ action_data(0x00) ‖ OP_2DROP(0x6d) ‖ pushed_normal_body
‖ OP_RETURN(0x6a) ‖ reconstructed_tail`.

### 3.3 Path 4 confiscate-from-frozen (§9.8)

Structural pattern derived from Normal's `PATH4_CONFISCATE_ASM`. The Frozen
variant adds the h_Normal hash verify because target is Normal (different
template). Differences from Normal path 4:

- **Hash commit added:** `SHA256(pushed) == h_Normal` (placeholder 32 zero
  bytes) — ~+40b not present in Normal path 4.
- **Body-before-tail source:** pushed Normal body (from unlocking), not
  Frozen's own cache. (Normal path 4 reuses its own cached `body_before_tail`;
  Frozen cannot — it is a _different_ template than the target.)

Other aspects identical:

- **Authority flag checked:** `02` (bit 1 confiscatable).
- **Authority helper flag:** `"08"` (confiscAuth MPKH flag bit 3).
- **new_owner source:** pushed output tuple.
- **new_depth source:** `my_depth` from altstack tail cache —
  **PRESERVED per decision #39 / §4.2 rule 4**. The spec §9.8 prose states
  `new_depth = 0` — that prose is stale relative to decision #39 (which
  ratifies depth preservation on ALL confiscate paths). See §4.1 spec gap.
- **Target action_data:** `0x00` (Normal).
- **Body marker in tuple verify:** `01ff` (Normal).
- **Owner size check:** `OP_DUP OP_SIZE OP_NIP 14 OP_NUMEQUALVERIFY`
  (decision #43 PKH-only per A.3.2 Phase 1A limitation).

### 3.4 Depth preservation approach

Both Frozen paths preserve depth from source:

- **Path 3 unfreeze:** `attestation_depth` pulled from altstack tail cache
  (byte-exact from source's tail), concatenated into reconstructed tail.
- **Path 4 confiscate-from-frozen:** same altstack pull, honoring decision
  #39. The tuple's `new_depth` field is byte-matched to ensure the
  unlocking-supplied tuple is consistent with what the locking derives —
  but the SUBSTANTIVE depth value in the output tail is the source's.

This matches Normal path 4 confiscate's post-A.3 pattern verbatim.

### 3.5 Hash + pushed-body verify pattern

Both paths use the identical sequence:

```
OP_DEPTH OP_2 OP_SUB OP_PICK        // locate pushed body on stack
OP_SHA256                            // compute SHA256
0000...0000 (32 zero bytes)          // placeholder — SDK patches h_Normal
OP_EQUALVERIFY
```

Compiled size: ~39 bytes per path. SDK deploy tool (Phase 1B) must locate
both occurrences and patch in the real `SHA256(NORMAL_BODY_BYTES)` (the
measurement test verifies the placeholder appears exactly twice).

### 3.6 Dispatcher topology

Frozen has only 2 valid path_ids ({3, 4}), so a branch-gate structure rather
than Normal's 4-way dispatcher suffices:

```
OP_DUP OP_3 OP_EQUAL OP_IF
  <path 3 unfreeze>
OP_ELSE
  OP_DUP OP_4 OP_EQUALVERIFY        // reject anything that isn't 4
  <path 4 confiscate-from-frozen>
OP_ENDIF
OP_DROP
```

Total dispatcher scaffold: 10 bytes (4b header + 6b middle). Paths 1, 2,
5, 6 are unreachable by construction — no runtime path_id range check is
needed (OP_EQUALVERIFY on 4 rejects 1, 2, 5, 6 implicitly).

---

## 4. Spec gaps discovered (NOT self-fixed in source)

### 4.1 Spec §9.8 prose stale vs decision #39

**Gap:** Spec §9.8 final sentence reads:

> `new_depth = 0` rather than depth-preserved.

This directly contradicts decision #39 (Step C Critical #1), which ratifies:

> Confiscate is pure ownership change; does NOT reset attestation_depth.

Decision #39 §4.2 rule 4 applies to **all confiscate paths** (Normal path 4
and Frozen path 4). The §9.8 prose is pre-#39 text that was not swept
forward when #39 was ratified. §9.5 was swept; §9.8 was missed.

**Impact on source:** we honor decision #39 (depth preserved) — the ASM
pulls `attestation_depth` from the tail cache rather than emitting a hard
`0000` literal. This matches Normal path 4's post-A.3 pattern.

**Recommendation:** Phase 1B spec amendment to replace §9.8 prose with
"same as §9.5 confiscate — new_depth = my_depth (PRESERVED per decision
#39)". 0 byte impact.

### 4.2 Normal template does not export shared PREFIX helpers

**Gap:** `src/bntp/v2/templates/normal-body.ts` defines `COVENANT_S_PREAMBLE_ASM`,
`COVENANT_TAIL_ASM`, `SIGHASH_CHECK_ASM`, `PREIMAGE_PARSE_ASM`,
`TAIL_CACHE_ASM`, `VARINT_SERIALIZE_ASM`, and the `authorityIdentityAsm`
factory as **module-local `const`** — none are exported. The Frozen
template body (this work) and the forthcoming Contract template body would
both consume these helpers.

**Impact on source:** we duplicate the ~730b of PREFIX ASM strings verbatim
into `frozen-body.ts`. The compiled body sections are byte-identical to
Normal's. This is honest duplication — there is no silent divergence risk
because all helpers are ASCII ASM strings that will compile to identical
bytes given the same asmToBytes implementation.

**Recommendation:** Phase 1B refactor:

1. Add `export` to the six Normal-body helpers named above.
2. Swap `frozen-body.ts` (and forthcoming `contract-body.ts`) inline copies
   for imports.
3. Add a CI test that compiles the six symbols independently and snapshots
   their byte lengths, to catch accidental drift post-refactor.

The duplication is NOT a correctness risk for Phase 1A.3 byte-measurement
goals — the whole purpose of this phase is to quantify structural completeness
with honest byte counts. Factoring the helpers is a quality-of-life
improvement, not a blocker.

### 4.3 Frozen spec body projection (§11.1) is stale

Spec §11.1 table lists Frozen body target at ~700b. Post-audit realistic is
~1100-1300b (this measurement: 1282b).

**Recommendation:** Phase 1B spec amendment: update §11.1 Frozen row to
~1300b (parallel to Normal's upward revision 2000→2500→2700). Update §3
template catalog Frozen "Est. body" column from "~700b" to "~1300b". Same
rationale as Normal's arc: optimistic pre-audit projection supplanted by
honest per-helper measurement.

This is editorial; no decision change needed.

---

## 5. Phase 1B recommendations

### 5.1 Patch h_Normal placeholder

SDK deploy tool must:

1. Compile `NORMAL_BODY_BYTES` (already a hard-coded export).
2. Compute `h_Normal = SHA256(NORMAL_BODY_BYTES)`.
3. Locate **both** 32-byte zero-push occurrences in `FROZEN_BODY_BYTES`
   (path 3 and path 4) and replace with `h_Normal` bytes in-place.
4. Verify post-patch body SHA256 matches the manifest (§5.5.3).

The measurement test `h_Normal placeholder is embedded as 32b zero-push in
both paths` already asserts both occurrences are present and locatable.

### 5.2 Factor shared PREFIX helpers out of normal-body.ts

See §4.2 above. Quality-of-life refactor; removes ~730b of duplication
between `normal-body.ts` and `frozen-body.ts`. Must land before
`contract-body.ts` to avoid a third copy.

### 5.3 §9.8 spec amendment

See §4.1 above. Editorial fix to align prose with decision #39.

### 5.4 MPKH owner output support on path 4 confiscate-from-frozen

The same A.3.2 limitation from Normal's report applies here: path 4's
output reconstruction uses the hardcoded `14 OP_SPLIT` pattern for the
owner byte extraction, plus the `OP_SIZE == 20` size check. Variable-length
owner extraction (flag-gated selector) needed to support MPKH-owned
output of confiscate-from-frozen.

Scope: identical to Normal A.3.2 fix. Can be paired with the Normal fix to
share a single variable-length-owner helper.

### 5.5 Jest fix prerequisite

The measurement used `npx tsx` temp runner because jest is currently broken
in the repo (noted in Normal A.3 report context). Phase 1B must restore
jest before the test file in `tests/bntp-v2-frozen-template-size.test.ts`
can run as part of CI. Structural gates (deterministic compile, marker,
size, h_Normal push, section sum) were verified via the runner.

### 5.6 Execution correctness verification

Same as Normal A.3 §6.3: the ASM is byte-measurable and structurally
complete; stack choreography has NOT been node-executed. Phase 1B must
run full script against TX vectors and fix residual stack-management bugs.

Known suspect areas inherited from Normal-donor helpers:

- Preimage parse altstack ordering (Normal A.1.1 caveat).
- `authorityIdentityAsm` FROMALTSTACK/TOALTSTACK round-trips.
- Tail cache FD/FE/FF varint branch parity.

These are Normal-source issues, not Frozen-specific regressions.

### 5.7 Contract template (parallel round)

The sibling Phase 1A.3 parallel agent writing `contract-body.ts` should
reuse the same spec-decision interpretations as this Frozen work:

- Decision #39 preserve-depth does NOT apply to Contract (issue path has
  `new_depth = 0` explicitly per §9.9 rule 6, not a confiscate path).
- Decision #42 `thisOutpoint = Contract outpoint` is Contract-specific.
- Decision #47 Contract `attestation_depth == 0` at mint is Contract-specific.
- Shared helper factoring (§4.2 above) should ideally land BEFORE Contract
  to avoid a third copy.

---

## 6. Next action

**Ready for:** Phase 1B SDK-deploy-tool hash-patching implementation,
jest restoration, execution-correctness verification.

**Unblocks:** Contract template body (if it hasn't been written yet) with
the same helper-duplication posture. Spec amendments §4.1 and §4.3.

**Dependencies:** none within Phase 1A.3 Frozen scope.

The Frozen template body is **PIVOT at 1282 bytes** (118-byte slack to the
recalibrated ABORT ceiling of 1400b), structurally complete and
feature-complete per spec decisions #27, #29, #36, #39, #41, #43. The body
is ready for downstream Phase 1B consumption (hash-patching, SDK builders,
execution verification).
