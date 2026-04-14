# DSTAS Locking Template (Freeze + Confiscation + Swap + Multisig)

This document summarizes the template behavior used by the SDK for Divisible STAS (DSTAS).

For transaction-level flow invariants, see `docs/DSTAS_SCRIPT_INVARIANTS.md`.

## Template Placeholders

The ASM template has variable placeholders:

- `<owner address/MPKH - 20 bytes>`
- `<action data>`
- `OP_RETURN <"redemption address"/"protocol ID" - 20 bytes> <flags field> <service data per each flag> <optional data field/s - upto around 4.2GB size>`

The SDK injects these fields in `src/script/build/dstas-locking-builder.ts`.

## How Base Tokens Are Built

- Source of truth: `src/script/templates/dstas-locking-template.ts`.
- Runtime base extraction: `src/script/templates/dstas-locking-template-base.ts` parses the ASM once and caches the base token list.
- This keeps the SDK aligned with template updates without manual opcode-table regeneration.

## Action Data Field (Freeze Marker)

- Empty action field, not frozen: `OP_0`.
- Empty action field, frozen: `OP_2`.
- Non-empty action field, frozen: prefixed by byte `0x02`.
- Unfreeze removes the frozen marker (`OP_2` -> `OP_0` or strips `0x02` prefix).

## Flags and Service Fields

Flags are pushdata bytes (not numeric opcodes).

- Bit 0 (`0x01`): freezable
- Bit 1 (`0x02`): confiscatable
- Both enabled: `0x03`

Service fields must follow flags and are ordered left-to-right:

1. freeze authority field (if freezable)
2. confiscation authority field (if confiscatable)

The SDK enforces `serviceFields.length` to match enabled bits exactly.

## Spending Type (Unlocking Script)

- `0`: reserved
- `1`: regular spending
- `2`: freeze/unfreeze
- `3`: confiscation
- `4`: swap cancellation

## Behavior Notes

- Frozen UTXOs can still be confiscated (confiscation authority path supersedes freeze restriction).
- Redemption is not valid while token is in frozen/confiscation-restricted state.
- Issuer-side redeem path uses P2MPKH-compatible behavior in current SDK flows.

## Internal Stack Invariants (Merge / Swap Path)

These are implicit contracts inside the template's `segCount!=0` branch that are
easy to break during edits. Record them here so future changes don't rediscover
them the hard way.

### 1. Counterparty script at stack depth 3 has a dual role

During merge/swap, the counterparty locking script sits at depth 3 (from altstack)
and is used for **two independent** purposes:

1. **Previous-tx reconstruction** — copied via `3 PICK` while splicing pieces
   back into the counterparty's previous transaction.
2. **Output verification** — later in the template it is compared against the
   output's locking script to check that outputs continue the same asset leg.

Consequence: do **not** replace or consume the value at depth 3 during
reconstruction. If you need a different counterparty script (as in swap, where
the two inputs hold different tokens), bring an additional `cp_merge` onto the
stack at an adjacent position, shift ROLL indices to account for it, and
`ROLL DROP` it after reconstruction so `cp_current` is restored to depth 3.

### 2. Value at stack depth 1 after merge/swap `ENDIF` is a swap flag

After the merge/swap section closes, the element that happens to be at stack
depth 1 later ends up at depth 5 and is tested via `5 PICK NOTIF` to decide
whether a subsequent `EQUALVERIFY` comparing counterparty scripts should run.

- `0` (falsy) → comparison runs → passes for merge (same token), would fail
  for swap (different tokens).
- `1` (truthy) → comparison is skipped → correct for swap.

Merge naturally leaves `remaining=0` there, which works by design. Old swap
(no reconstruction) left `segCount=1` there, which also worked — by accident.
New swap performs a full reconstruction and also ends with `remaining=0`, so
the template explicitly inverts it with `SWAP NOT SWAP` before closing the
branch. If you refactor the merge/swap path, preserve this contract: **depth 1
on exit must be `0` for merge and `1` for swap**.

### 3. Data marker must track body size

The template body contains a literal hex marker (currently `8a0b` = 2954) that
encodes the byte offset of `OP_RETURN` within the body. It is used by
`OP_SPLIT` to carve out tokenId from an output's counterparty script. Any edit
that changes the size of the body before `OP_RETURN` **must** update this
marker; otherwise conformance and swap tests fail in places that look unrelated
to the edit.

Formula: `marker = (bytes before OP_RETURN in body) + 2`
(the `+2` covers the `OP_RETURN` opcode byte and the push-length byte that
follows it).

## Builder API

- `buildDstasLockingTokens(params)`
- `buildDstasLockingScript(params)`
- `buildDstasLockingAsm(params)`

## Example

```ts
import { dstas, bsv } from "dxs-bsv-token-sdk";

const script = dstas.buildDstasLockingScript({
  ownerPkh: bsv.fromHex("2f2ec98dfa6429a028536a6c9451f702daa3a333"),
  redemptionPkh: bsv.fromHex("b4ab0fffa02223a8a40d9e7f7823e61b38625382"),
  actionData: null,
  frozen: false,
  flags: new Uint8Array([0x03]), // freeze + confiscation
  serviceFields: [
    bsv.fromHex("00112233445566778899aabbccddeeff00112233"), // freeze authority
    bsv.fromHex("8899aabbccddeeff00112233445566778899aabb"), // confiscation authority
  ],
  optionalData: [],
});

console.log(script);
```
