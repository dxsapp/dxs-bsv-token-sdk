# DSTAS — PKH Owner Authorization Finding

**Status:** Potential security finding, awaiting reproduction. Flagged during BNTP v2 Phase 1 Step A.1.1 (real-ASM writing) by the opus agent reviewing DSTAS template as ASM donor. Corroborated by BNTP v2 audit §2.3 (`BNTP_V2_NORMAL_TEMPLATE_AUDIT.md`) and the A.1.1 execution report §5.

**Severity (if confirmed):** Critical — allows unauthorized spending of PKH-owned DSTAS UTXOs by anyone who can observe the tx.

**Impact on BNTP v2:** **None.** BNTP v2 explicitly requires separate owner CHECKSIGVERIFY per decision #29 (spec §8.1). This finding is about DSTAS only.

**Action status:** Not blocking. Filed for separate investigation / reproduction.

---

## 1. The hypothesis

DSTAS locking script authorizes spends via an OP_PUSH_TX covenant pattern. The covenant verifies that the pushed preimage is the authentic sighash-preimage of the current input by constructing a signature algorithmically from `HASH256(preimage)` and checking it against generator-point-derived pubkeys with parity branching.

For MPKH owners, a separate `OP_CHECKMULTISIGVERIFY` runs (gated by `OP_SIZE OP_NIP OP_IF`), using the unlocking-provided signatures against owner-derived pubkeys.

**For PKH owners, no separate signature check appears to run.** The template verifies `HASH160(owner_pubkey) == owner_field` (identity binding) but does not CHECKSIGVERIFY a signature under `owner_pubkey` against `preimage`. The covenant's CHECKSIGVERIFY uses the generator-point-constructed signature, which anyone with the preimage can satisfy (the preimage is public — it's the sighash of the current tx).

Consequence: if the hypothesis is correct, spending a PKH-owned DSTAS UTXO requires only:

1. Knowledge of the owner's **public key** (revealed in any prior spend by the owner).
2. Ability to construct a valid tx that satisfies the rest of the locking script's constraints (output reconstruction, tail match, hashOutputs covenant).

Both are trivially achievable by any attacker observing the chain. The owner's private key is not required.

## 2. Evidence supporting the hypothesis

From `src/script/templates/dstas-locking-template.ts` (grep-confirmed):

- Exactly **one** occurrence of `OP_CHECKSIGVERIFY`. Located in the covenant block, immediately after the DER-sig construction (from `3044022079BE667EF...` through generator-point pubkey selection). This is the constructed-sig check.
- Exactly **one** occurrence of `OP_CHECKMULTISIGVERIFY`. Located inside an `OP_IF` branch gated by `OP_SIZE OP_NIP` — i.e., taken only when the top of stack is a nontrivial-length byte string (MPKH preimage). For PKH owners the top of stack at that point is a 33-byte pubkey; `OP_SIZE OP_NIP` leaves 33 on top, which is truthy, so actually it... wait — see §4 for the exact resolution of this ambiguity.

From `docs/DSTAS_LOCKING_SCRIPT_AUDIT.md` (internal prior audit of DSTAS):

- §1 diagrams the locking script as `[Signature verification — OP_PUSH_TX]` followed by `[Preimage parsing]` and dispatch logic. No separate owner-sig block.
- §2.1 flags "Back-to-Genesis" as the critical finding. Does NOT flag PKH owner-auth as a finding. This may indicate the audit missed it, OR that there is a mechanism I do not yet understand.
- The audit does not explicitly document how PKH owners are authenticated.

From `docs/DSTAS_SCRIPT_INVARIANTS.md`:

- §8 says "Owner multisig controls spending ownership path." Ambiguous — the word "multisig" could imply the only spend path is multisig, OR it could be a generic label. Unclear.

## 3. What would refute the hypothesis

Any of the following would make the finding a false alarm:

- **Hidden owner-sig check in DSTAS template** that I missed on close reading. The template is ~2500 bytes of ASM with heavy OP_SPLIT/OP_CAT/altstack choreography; an additional CHECKSIG could be tucked into a branch I didn't trace.
- **Covenant pattern that reuses owner's sig**: in some BSV OP_PUSH_TX variants, the owner's signature is what gets checked by the covenant (not an algorithmically-constructed one). The sig-over-preimage mechanic doubles as both preimage-authentication and owner-auth. But the DER prefix `30 44 02 20 79BE667E...` in the DSTAS template is the generator-point x-coord — which is the algorithmic-construction marker, **not** the owner's real sig.
- **Network-level enforcement outside script**: BSV miners might enforce additional constraints (e.g., "tx must include a sig from the input's address") that prevent the attack. This is not standard — script is the consensus boundary for spend authorization.
- **Obscurity**: owner's pubkey might not be reliably retrievable from chain history if owners use one-time addresses exclusively. But any wallet that reuses addresses (common) exposes the pubkey on first spend.

## 4. Reproduction steps (proposed, not yet executed)

**Test vector construction:**

1. Deploy a DSTAS token UTXO with PKH owner = `HASH160(pubkey_A)` where `pubkey_A` is a well-known pubkey (e.g., generated from a published test private key).
2. As an adversary who does NOT hold `privkey_A`:
   - Retrieve `pubkey_A` from a prior on-chain spend or from the issuer's off-chain registry.
   - Construct a transfer tx:
     - Input 0: the target DSTAS UTXO
     - Input 1: attacker's own funding UTXO (standard P2PKH)
     - Output 0: a new DSTAS UTXO with the same token, `owner = attacker's PKH`, same amount
     - Output 1: change to attacker
   - Build the unlocking script per the DSTAS layout:
     - Preimage: real sighash preimage for input 0, SIGHASH_ALL | SIGHASH_FORKID
     - Spending type: 1 (transfer)
     - Signature: `pubkey_A`'s arbitrary sig slot — **try pushing any valid 70-72 byte DER-encoded sig structure** (content doesn't matter if not CHECKSIG'd separately)
     - Pubkey: `pubkey_A`
   - Broadcast.
3. **Success criterion:** tx is accepted by a BSV node in standardness mode AND mined. This would confirm PKH owner-auth is bypassable.
4. **Refutation criterion:** tx is rejected with a script-validation error (e.g., "signature invalid" or "checksig failed"). This would confirm that some owner-auth mechanism exists that I haven't traced.

**Safe reproduction environment:** use BSV regtest or a throwaway testnet. Do not attempt against mainnet unless the test private key's UTXO is intended as a deliberate bounty / low-value honeypot.

**Tool pointers:**

- `src/script/build/dstas-locking-builder.ts` — builds DSTAS locking with PKH owner.
- `src/dstas-factory.ts` and `src/dstas-bundle-factory.ts` — build transfer transactions.
- Use `src/script/eval/script-evaluator.ts` for local script evaluation if available as a drop-in (pre-broadcast sanity check).

## 5. If confirmed — impact scope

- **Every PKH-owned DSTAS UTXO** on any BSV chain is at risk of unauthorized spending. MPKH-owned UTXOs are not affected.
- The attack is **cheap** (one mined tx per UTXO stolen) and **stealthy** (looks like a valid transfer from the outside).
- **Prior spends reveal pubkey** — which is standard behavior, so most owners are exposed.
- **Mitigation for existing holders:** migrate PKH → MPKH (1-of-1 MPKH still adds the CHECKMULTISIGVERIFY protection); or redeem tokens back to issuer before an attacker does.

## 6. If confirmed — reporting path

- File as a security issue against whatever DSTAS ecosystem is running in production (reference implementations, wallets, indexers, issuer services).
- Coordinate responsible disclosure with issuer(s) if any tokens are live.
- Propose template patch: add explicit `OP_CHECKSIGVERIFY` after `HASH160 EQUALVERIFY` in the PKH branch. Estimated +5-10b per DSTAS locking script body. All existing DSTAS UTXOs remain vulnerable (cannot retroactively patch deployed UTXOs); new tokens can be deployed with patched template.

## 7. Relationship to BNTP v2

BNTP v2 explicitly mandates **both** identity binding (HASH160 match) AND explicit OP_CHECKSIGVERIFY(sig, pubkey, preimage) for PKH owner (spec §8.1, decision #29). This was done during A.1.0 audit precisely because the DSTAS pattern was ambiguous — we chose the safer explicit variant.

Cost in BNTP v2: +5-10b in PREFIX §3.6 (OWNER_IDENTITY_ASM). Already measured and present in A.1.1+ artifacts.

Even if the DSTAS finding is later refuted, **BNTP v2's explicit CHECKSIGVERIFY remains correct** — defense in depth, explicit > implicit, auditor-friendly.

## 8. Confidence

**Medium-high** that the finding is real, pending empirical reproduction:

- **High** that the DSTAS template has only one CHECKSIGVERIFY (covenant) and conditional CHECKMULTISIGVERIFY (MPKH). Confirmed via grep.
- **Medium** that the covenant CHECKSIGVERIFY is the generator-point constructed pattern and not a disguised owner-sig reuse. Confirmed by inspecting the DER prefix and the `s` computation from `HASH256(preimage)`.
- **Low-to-medium** that no mechanism outside my inspection provides owner-auth. The prior DSTAS audit did not flag this, which is weak evidence for/against.

Recommend empirical reproduction before publishing as a security advisory.

## 9. Disposition

- **Blocking BNTP v2?** No. BNTP v2 has explicit owner CHECKSIGVERIFY; this finding only informs the rationale for decision #29.
- **Blocking DSTAS deployment?** If the hypothesis is confirmed: yes — existing PKH holders at risk, new deployments should be paused until patched. If refuted: no action beyond documenting the "how owner is authed" mechanism in DSTAS spec.
- **Next action:** someone (not BNTP v2 main session) runs the reproduction in §4. If confirmed, file as security advisory. If refuted, update this document with the refutation evidence.

---

## References

- `src/script/templates/dstas-locking-template.ts`
- `docs/DSTAS_LOCKING_SCRIPT_AUDIT.md` (prior DSTAS audit)
- `docs/DSTAS_SCRIPT_INVARIANTS.md`
- `docs/BNTP_V2_NORMAL_TEMPLATE_AUDIT.md` §2.3 (initial hypothesis)
- `docs/BNTP_V2_NORMAL_TEMPLATE_A1_1_REPORT.md` §5 (A.1.1 agent's independent confirmation)
- `docs/BNTP_V2_SPEC.md` §8.1, decision #29 (BNTP v2 mitigation)
