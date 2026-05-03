import { ethers, zkit } from "hardhat";
import { formatPrivKeyForBabyJub, genPrivKey } from "maci-crypto";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { poseidon3 } from "poseidon-lite";
import { processPoseidonEncryption, encryptMetadata } from "../src";
import { withdrawIntent } from "../test/helpers";
import type { RegistrationCircuit, WithdrawIntentCircuit } from "../generated-types/zkit";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

// ── Latest Fuji deployment ────────────────────────────────────────────────────
const CONTRACTS = {
    registrar:    "0xe2d281288637CF6164986793C52C32928A74ec57",
    encryptedERC: "0x69c975f94aaA927906c29b16a09eDA25A1Da4E7C",
    erc20:        "0xFC3b7551Af3a5Dd802229223069c134ad543895D",
};

const ERC20_DECIMALS     = 18;
const CONTRACT_DECIMALS  = 2;   // contract's internal decimals (from constants.ts)
const SCALING_FACTOR     = 10n ** BigInt(ERC20_DECIMALS - CONTRACT_DECIMALS); // 10^16
const DEPOSIT_AMOUNT     = ethers.parseEther("100");   // 100 TEST in ERC20 units (18 dec)
const INTERNAL_AMOUNT    = DEPOSIT_AMOUNT / SCALING_FACTOR; // 10000 — internal units stored in ElGamal
const DENOMINATION       = ethers.parseEther("100");   // denomination in token's own decimals
const NONCE              = 1n;
const BATCH_WINDOW_INDEX = 0n; // 86400s = 1 day
const DENOMINATION_INDEX = 0n;

const KEY_FILE    = path.join(__dirname, "fuji-key.json");
const DATA_FILE   = path.join(__dirname, "fuji-intent-data.json");
const INFO_FILE   = path.join(__dirname, "../../../info.md");

// ── BabyJubJub key helpers ────────────────────────────────────────────────────

function loadOrCreateKey() {
    if (fs.existsSync(KEY_FILE)) {
        const raw = JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
        return {
            privateKey:          BigInt(raw.privateKey),
            formattedPrivateKey: BigInt(raw.formattedPrivateKey),
            publicKey:           raw.publicKey.map(BigInt) as [bigint, bigint],
        };
    }
    const privateKey          = genPrivKey();
    const formattedPrivateKey = formatPrivKeyForBabyJub(privateKey) % subOrder;
    const publicKey           = mulPointEscalar(Base8, formattedPrivateKey).map(BigInt) as [bigint, bigint];
    fs.writeFileSync(KEY_FILE, JSON.stringify({
        privateKey:          privateKey.toString(),
        formattedPrivateKey: formattedPrivateKey.toString(),
        publicKey:           publicKey.map(String),
    }, null, 2));
    console.log("  New BabyJubJub key generated and saved to fuji-key.json");
    return { privateKey, formattedPrivateKey, publicKey };
}

function genRegistrationHash(chainId: bigint, formattedPrivateKey: bigint, address: string): bigint {
    return poseidon3([chainId, formattedPrivateKey, BigInt(address)]);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    console.log("\n=== Avacado Fuji Bootstrap (Steps 1–4) ===\n");

    const [deployer] = await ethers.getSigners();
    console.log("Deployer:", deployer.address);

    const avaxBalance = await ethers.provider.getBalance(deployer.address);
    console.log("AVAX balance:", ethers.formatEther(avaxBalance));

    const registrar    = await ethers.getContractAt("Registrar",    CONTRACTS.registrar,    deployer);
    const encryptedERC = await ethers.getContractAt("EncryptedERC", CONTRACTS.encryptedERC, deployer);
    const erc20        = await ethers.getContractAt("SimpleERC20",  CONTRACTS.erc20,        deployer);

    const network = await ethers.provider.getNetwork();
    const chainId = BigInt(network.chainId);
    console.log("Chain ID:", chainId.toString());

    // ── Load or create BabyJubJub key ─────────────────────────────────────────
    console.log("\n[Key] Loading BabyJubJub key...");
    const { privateKey, formattedPrivateKey, publicKey } = loadOrCreateKey();
    console.log("  Public key[0]:", publicKey[0].toString().slice(0, 20) + "...");

    // ── Step 1: Register ──────────────────────────────────────────────────────
    console.log("\n[Step 1] Registration...");
    const alreadyRegistered = await registrar.isUserRegistered(deployer.address);

    if (alreadyRegistered) {
        console.log("  Already registered — skipping.");
    } else {
        const registrationCircuit = await zkit.getCircuit("RegistrationCircuit");
        const registrationHash    = genRegistrationHash(chainId, formattedPrivateKey, deployer.address);

        const proof    = await (registrationCircuit as unknown as RegistrationCircuit).generateProof({
            SenderPrivateKey:  formattedPrivateKey,
            SenderPublicKey:   publicKey,
            SenderAddress:     BigInt(deployer.address),
            ChainID:           chainId,
            RegistrationHash:  registrationHash,
        });
        const calldata = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proof);

        const tx = await registrar.register({
            proofPoints:   calldata.proofPoints,
            publicSignals: calldata.publicSignals,
        });
        await tx.wait();
        console.log("  Registered. tx:", tx.hash);
    }

    // ── Step 2: Deposit ───────────────────────────────────────────────────────
    console.log("\n[Step 2] Deposit...");

    let tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
    const existingBalance = tokenId > 0n
        ? await encryptedERC.balanceOf(deployer.address, tokenId)
        : null;
    const alreadyDeposited = existingBalance && existingBalance.amountPCTs.length > 0;

    let depositTxHash = "already deposited — skipped";
    if (alreadyDeposited) {
        console.log("  Balance exists — skipping deposit.");
        console.log("  tokenId:", tokenId.toString());
    } else {
        // Approve if needed
        const allowance = await erc20.allowance(deployer.address, CONTRACTS.encryptedERC);
        if (allowance < DEPOSIT_AMOUNT) {
            const approveTx = await erc20.approve(CONTRACTS.encryptedERC, DEPOSIT_AMOUNT);
            await approveTx.wait();
            console.log("  Approved EncryptedERC to spend TEST tokens.");
        }

        const {
            ciphertext: depositCt,
            nonce:      depositNonce,
            authKey:    depositAuthKey,
        } = processPoseidonEncryption([DEPOSIT_AMOUNT], publicKey);

        const depositTx = await (encryptedERC as any)["deposit(uint256,address,uint256[7])"](
            DEPOSIT_AMOUNT,
            CONTRACTS.erc20,
            [...depositCt, ...depositAuthKey, depositNonce],
        );
        await depositTx.wait();
        depositTxHash = depositTx.hash;
        console.log("  Deposited 100 TEST. tx:", depositTx.hash);

        tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
        console.log("  tokenId:", tokenId.toString());
    }

    // ── Step 3: Set denominations ─────────────────────────────────────────────
    console.log("\n[Step 3] Set denominations...");
    const existingDenoms = await encryptedERC.getDenominations(tokenId);
    if (existingDenoms.length > 0) {
        console.log("  Already set:", existingDenoms.map((d: bigint) => ethers.formatEther(d)).join(", "), "TEST");
    } else {
        const setDenomTx = await encryptedERC.setDenominations(tokenId, [DENOMINATION]);
        await setDenomTx.wait();
        console.log("  Denominations set: [100 TEST]. tx:", setDenomTx.hash);
    }

    // ── Step 4: Submit withdraw intent ────────────────────────────────────────
    console.log("\n[Step 4] Submit withdraw intent...");

    // Check if a pending intent already exists on-chain
    const hasPendingIntent = await (encryptedERC as any).pendingIntents(deployer.address, tokenId);
    if (hasPendingIntent) {
        console.log("  Pending intent already exists on-chain.");
        if (fs.existsSync(DATA_FILE)) {
            console.log("  fuji-intent-data.json exists — use fuji-execute-batch.ts when ready.");
            return;
        }
        console.log("  WARNING: pending intent exists but no data file found. Intent data may be lost.");
        return;
    }

    const balance = await encryptedERC.balanceOf(deployer.address, tokenId);
    const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

    const auditorPubKeyRaw = await encryptedERC.auditorPublicKey();
    const auditorPublicKey: bigint[] = [auditorPubKeyRaw[0], auditorPubKeyRaw[1]];

    // Build a mock User-like object for the withdrawIntent helper
    const userForHelper = {
        privateKey,
        formattedPrivateKey,
        publicKey,
        signer: deployer,
        address: BigInt(deployer.address),
        genRegistrationHash: (cid: bigint) => genRegistrationHash(cid, formattedPrivateKey, deployer.address),
        getAddress: () => deployer.address,
    } as any;

    const { proof: intentCalldata, userBalancePCT, intentHash } = await withdrawIntent(
        INTERNAL_AMOUNT,      // ValueToWithdraw — internal units (10000)
        deployer.address,
        tokenId,
        NONCE,
        userForHelper,
        userEncryptedBalance,
        INTERNAL_AMOUNT,      // SenderBalance — internal units (10000)
        auditorPublicKey,
    );

    const MESSAGE = "Avacado Fuji batch test — 24h intent";
    const encryptedMeta = encryptMetadata(publicKey, MESSAGE);

    const submitTx = await encryptedERC.submitWithdrawIntent(
        tokenId,
        DENOMINATION_INDEX,
        BATCH_WINDOW_INDEX,
        intentCalldata,
        userBalancePCT,
        encryptedMeta,
    );
    const submitReceipt = await submitTx.wait();

    const submitBlock = await ethers.provider.getBlock(submitReceipt!.blockNumber);
    const submitTimestamp = Number(submitBlock!.timestamp);
    const executeAfter    = submitTimestamp + 86400;

    const submitEvents = submitReceipt!.logs
        .map((log: any) => {
            try { return encryptedERC.interface.parseLog({ topics: log.topics, data: log.data }); }
            catch { return null; }
        })
        .filter((e: any) => e?.name === "WithdrawIntentSubmitted");

    const onChainIntentHash = submitEvents[0]?.args?.intentHash;
    console.log("  Intent submitted. tx:", submitTx.hash);
    console.log("  intentHash:", onChainIntentHash);
    console.log("  Execute after:", new Date(executeAfter * 1000).toISOString(), "(24h from now)");

    // ── Serialize proof data ──────────────────────────────────────────────────
    const serialize = (v: any): any => {
        if (typeof v === "bigint") return v.toString();
        if (Array.isArray(v)) return v.map(serialize);
        if (typeof v === "object" && v !== null) {
            return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, serialize(val)]));
        }
        return v;
    };

    const intentData = {
        intentHash:       onChainIntentHash,
        tokenId:          tokenId.toString(),
        destination:      deployer.address,
        amount:           INTERNAL_AMOUNT.toString(), // internal units (contract decimals)
        nonce:            NONCE.toString(),
        proof:            serialize(intentCalldata),
        userBalancePCT:   userBalancePCT.map(String),
        intentMetadata:   encryptedMeta,
        submitTimestamp,
        executeAfter,
        contracts:        CONTRACTS,
    };

    fs.writeFileSync(DATA_FILE, JSON.stringify(intentData, null, 2));
    console.log("\n  Intent data saved to fuji-intent-data.json");

    // ── Write info.md ─────────────────────────────────────────────────────────
    const infoMd = `# Fuji Batch Test — Intent Submitted

## Status

Steps 1–4 complete. Intent is live on Fuji testnet.
Come back after **${new Date(executeAfter * 1000).toUTCString()}** to execute.

## Intent Details

| Field | Value |
|---|---|
| intentHash | \`${onChainIntentHash}\` |
| tokenId | \`${tokenId}\` |
| destination | \`${deployer.address}\` |
| amount | 100 TEST (internal: ${INTERNAL_AMOUNT}) |
| nonce | ${NONCE} |
| submitted at | ${new Date(submitTimestamp * 1000).toUTCString()} |
| executable after | **${new Date(executeAfter * 1000).toUTCString()}** |

## Transactions

| Step | tx |
|---|---|
| 1. Register | \`${alreadyRegistered ? "already registered" : "see console"}\` |
| 2. Deposit 100 TEST | \`${depositTxHash}\` |
| 4. Submit intent | \`${submitTx.hash}\` |

[View contract on Snowtrace](https://testnet.snowtrace.io/address/${CONTRACTS.encryptedERC})

## How to Execute Tomorrow

\`\`\`bash
cd TrulyEncryptedERC
npx hardhat run scripts/fuji-execute-batch.ts --network fuji
\`\`\`

## Contract Addresses

| Contract | Address |
|---|---|
| EncryptedERC | \`${CONTRACTS.encryptedERC}\` |
| Registrar | \`${CONTRACTS.registrar}\` |
| TEST token | \`${CONTRACTS.erc20}\` |

## Data Files

- \`TrulyEncryptedERC/scripts/fuji-key.json\` — BabyJubJub key (keep safe)
- \`TrulyEncryptedERC/scripts/fuji-intent-data.json\` — proof + intent data for execution
`;

    fs.writeFileSync(INFO_FILE, infoMd);
    console.log("  info.md written.\n");

    console.log("=== Bootstrap complete ===");
    console.log(`Execute batch after: ${new Date(executeAfter * 1000).toISOString()}`);
    console.log("Run tomorrow: npx hardhat run scripts/fuji-execute-batch.ts --network fuji\n");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
