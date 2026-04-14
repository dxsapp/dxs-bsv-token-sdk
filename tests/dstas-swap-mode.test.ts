import { Wallet } from "../src/bitcoin/wallet";
import { OutPoint } from "../src/bitcoin/out-point";
import { ScriptType } from "../src/bitcoin/script-type";
import { ScriptBuilder } from "../src/script/build/script-builder";
import {
  buildDstasFlags,
  buildDstasLockingTokens,
} from "../src/script/build/dstas-locking-builder";
import {
  buildDstasLockingScriptForOwnerField,
  decomposeDstasUnlockingScript,
  extractDstasCounterpartyScript,
  splitDstasPreviousTransactionByCounterpartyScript,
} from "../src/script";
import { buildSwapActionData } from "../src/script/dstas-action-data";
import { ResolveDstasSwapMode } from "../src/dstas-factory";
import { OpCode } from "../src/bitcoin/op-codes";
import { concat, fromHex, toHex } from "../src/bytes";

type ScriptChunk = { op: OpCode } | { data: Uint8Array } | { number: number };

const buildUnlockingScript = (chunks: ScriptChunk[]): Uint8Array => {
  const builder = new ScriptBuilder(ScriptType.unknown);
  for (const chunk of chunks) {
    if ("op" in chunk) builder.addOpCode(chunk.op);
    else if ("number" in chunk) builder.addNumber(chunk.number);
    else builder.addData(chunk.data);
  }
  return builder.toBytes();
};

const mnemonic =
  "group spy extend supreme monkey judge avocado cancel exit educate modify bubble";

const tokenId = fromHex("b4ab0fffa02223a8a40d9e7f7823e61b38625382");

const makeDstasOutPoint = (
  txIdHexByte: string,
  owner: Wallet,
  actionData: Uint8Array | null,
): OutPoint => {
  const tokens = buildDstasLockingTokens({
    owner: owner.Address.Hash160,
    actionData,
    redemptionPkh: tokenId,
    frozen: false,
    flags: buildDstasFlags({ freezable: false }),
    serviceFields: [],
    optionalData: [],
  });
  const lockingScript = ScriptBuilder.fromTokens(tokens, ScriptType.dstas);
  return new OutPoint(
    txIdHexByte.repeat(64),
    0,
    lockingScript.toBytes(),
    100,
    owner.Address,
    ScriptType.dstas,
  );
};

const buildSyntheticSwapUnlockingScript = ({
  counterpartyPieces,
  counterpartyScript,
  piecesCount = counterpartyPieces.length,
  preimage = new Uint8Array(120).fill(0x11),
  signature = new Uint8Array(72).fill(0x30),
  publicKey = new Uint8Array(33).fill(0x02),
  spendingType = 1,
}: {
  counterpartyPieces: Uint8Array[];
  counterpartyScript: Uint8Array;
  piecesCount?: number;
  preimage?: Uint8Array;
  signature?: Uint8Array;
  publicKey?: Uint8Array;
  spendingType?: number;
}): Uint8Array =>
  buildUnlockingScript([
    ...counterpartyPieces.map((piece) => ({ data: piece })),
    { number: piecesCount },
    { data: counterpartyScript },
    { data: preimage },
    { number: spendingType },
    { data: signature },
    { data: publicKey },
  ]);

const reconstructCounterpartyTransaction = (
  counterpartyPieces: Uint8Array[],
  counterpartyScript: Uint8Array,
): Uint8Array =>
  concat(
    counterpartyPieces.flatMap((piece, index) =>
      index === counterpartyPieces.length - 1
        ? [piece]
        : [piece, counterpartyScript],
    ),
  );

const buildSwapUnlockingPrefix = (): Uint8Array =>
  buildUnlockingScript([
    { number: 100 },
    { data: fromHex("11".repeat(20)) },
    { op: OpCode.OP_0 },
    { op: OpCode.OP_0 },
    { op: OpCode.OP_0 },
    { number: 1 },
    { data: fromHex("44".repeat(32)) },
    { op: OpCode.OP_0 },
  ]);

describe("ResolveDstasSwapMode", () => {
  test("returns transfer-swap when only one input has swap actionData", () => {
    const owner =
      Wallet.fromMnemonic(mnemonic).deriveWallet("m/44'/236'/0'/0/0");
    const swapAction = buildSwapActionData({
      requestedScriptHash: new Uint8Array(32).fill(0x11),
      requestedPkh: owner.Address.Hash160,
      rateNumerator: 3,
      rateDenominator: 2,
    });

    const transferLike = {
      OutPoint: makeDstasOutPoint("1", owner, null),
      Owner: owner,
    };
    const swapLike = {
      OutPoint: makeDstasOutPoint("2", owner, swapAction),
      Owner: owner,
    };

    const mode = ResolveDstasSwapMode([transferLike, swapLike]);
    expect(mode).toBe("transfer-swap");
  });

  test("returns swap-swap when both inputs have swap actionData", () => {
    const owner =
      Wallet.fromMnemonic(mnemonic).deriveWallet("m/44'/236'/0'/0/0");
    const swapAction = buildSwapActionData({
      requestedScriptHash: new Uint8Array(32).fill(0x22),
      requestedPkh: owner.Address.Hash160,
      rateNumerator: 5,
      rateDenominator: 4,
    });

    const left = {
      OutPoint: makeDstasOutPoint("3", owner, swapAction),
      Owner: owner,
    };
    const right = {
      OutPoint: makeDstasOutPoint("4", owner, swapAction),
      Owner: owner,
    };

    const mode = ResolveDstasSwapMode([left, right]);
    expect(mode).toBe("swap-swap");
  });

  test("decomposes new swap unlock fields from the tail", () => {
    const script = concat([
      buildSwapUnlockingPrefix(),
      buildSyntheticSwapUnlockingScript({
        counterpartyPieces: [fromHex("aa"), fromHex("bb")],
        counterpartyScript: fromHex("cc".repeat(8)),
      }),
    ]);

    const decoded = decomposeDstasUnlockingScript(script);

    expect(decoded.parsed).toBe(true);
    expect(decoded.spendingType).toBe(1);
    expect(decoded.counterpartyPiecesCount).toBe(2);
    expect(decoded.counterpartyPiecesHexes).toEqual(["aa", "bb"]);
    expect(decoded.counterpartyScriptHex).toBe("cccccccccccccccc");
  });

  test("rejects swap unlock when piecesCount overstates the available pieces", () => {
    const decoded = decomposeDstasUnlockingScript(
      concat([
        buildSwapUnlockingPrefix(),
        buildSyntheticSwapUnlockingScript({
          counterpartyPieces: [fromHex("aa"), fromHex("bb")],
          piecesCount: 3,
          counterpartyScript: fromHex("cc".repeat(8)),
        }),
      ]),
    );

    expect(decoded.parsed).toBe(false);
    expect(decoded.errors.length).toBeGreaterThan(0);
  });

  test("rejects swap unlock when a declared piece is missing", () => {
    const decoded = decomposeDstasUnlockingScript(
      concat([
        buildSwapUnlockingPrefix(),
        buildSyntheticSwapUnlockingScript({
          counterpartyPieces: [fromHex("aa")],
          piecesCount: 2,
          counterpartyScript: fromHex("cc".repeat(8)),
        }),
      ]),
    );

    expect(decoded.parsed).toBe(false);
    expect(decoded.errors.length).toBeGreaterThan(0);
  });

  test("wrong counterparty script changes the reconstructed previous transaction", () => {
    const owner =
      Wallet.fromMnemonic(mnemonic).deriveWallet("m/44'/236'/0'/0/0");
    const correctLockingScript = buildDstasLockingScriptForOwnerField({
      ownerField: owner.Address.Hash160,
      tokenIdHex: toHex(tokenId),
      freezable: true,
      confiscatable: true,
      authorityServiceField: new Uint8Array(20).fill(0x11),
      confiscationAuthorityServiceField: new Uint8Array(20).fill(0x22),
      frozen: false,
    });
    const wrongLockingScript = buildDstasLockingScriptForOwnerField({
      ownerField: owner.Address.Hash160,
      tokenIdHex: toHex(tokenId),
      freezable: true,
      confiscatable: true,
      authorityServiceField: new Uint8Array(20).fill(0x33),
      confiscationAuthorityServiceField: new Uint8Array(20).fill(0x44),
      frozen: true,
    });

    const correctCounterpartyScript =
      extractDstasCounterpartyScript(correctLockingScript);
    const wrongCounterpartyScript =
      extractDstasCounterpartyScript(wrongLockingScript);
    const sourcePreviousTransaction = reconstructCounterpartyTransaction(
      [fromHex("11"), fromHex("22"), fromHex("33")],
      correctCounterpartyScript,
    );

    const decoded = decomposeDstasUnlockingScript(
      concat([
        buildSwapUnlockingPrefix(),
        buildSyntheticSwapUnlockingScript({
          counterpartyPieces: splitDstasPreviousTransactionByCounterpartyScript(
            sourcePreviousTransaction,
            correctCounterpartyScript,
          ),
          counterpartyScript: wrongCounterpartyScript,
        }),
      ]),
    );

    expect(decoded.parsed).toBe(true);
    expect(decoded.counterpartyScriptHex).toBe(toHex(wrongCounterpartyScript));
    expect(decoded.counterpartyScriptHex).not.toBe(
      toHex(correctCounterpartyScript),
    );
    expect(
      toHex(
        reconstructCounterpartyTransaction(
          decoded.counterpartyPiecesHexes.map(fromHex),
          wrongCounterpartyScript,
        ),
      ),
    ).not.toBe(toHex(sourcePreviousTransaction));
  });

  test("reordered counterparty pieces reconstruct a different previous transaction", () => {
    const counterpartyScript = fromHex("cc".repeat(8));
    const sourcePreviousTransaction = reconstructCounterpartyTransaction(
      [fromHex("11"), fromHex("22"), fromHex("33")],
      counterpartyScript,
    );
    const pieces = splitDstasPreviousTransactionByCounterpartyScript(
      sourcePreviousTransaction,
      counterpartyScript,
    );
    const reorderedPieces = [pieces[1], pieces[0], pieces[2]];

    const decoded = decomposeDstasUnlockingScript(
      concat([
        buildSwapUnlockingPrefix(),
        buildSyntheticSwapUnlockingScript({
          counterpartyPieces: reorderedPieces,
          counterpartyScript,
        }),
      ]),
    );

    expect(decoded.parsed).toBe(true);
    expect(decoded.counterpartyPiecesHexes).toEqual(
      reorderedPieces.map((piece) => toHex(piece)),
    );
    expect(
      toHex(
        reconstructCounterpartyTransaction(reorderedPieces, counterpartyScript),
      ),
    ).not.toBe(toHex(sourcePreviousTransaction));
  });
});
