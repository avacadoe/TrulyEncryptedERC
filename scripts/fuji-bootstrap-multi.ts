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
const CONTRACT_DECIMALS  = 2;
const SCALING_FACTOR     = 10n ** BigInt(ERC20_DECIMALS - CONTRACT_DECIMALS); // 10^16
const DEPOSIT_AMOUNT     = ethers.parseEther("100");   // 100 TEST ERC20 units
const INTERNAL_AMOUNT    = DEPOSIT_AMOUNT / SCALING_FACTOR; // 10000 — internal units
const DENOMINATION       = ethers.parseEther("100");
const NONCE              = 1n;
const BATCH_WINDOW_INDEX = 0n; // 86400s = 1 day
const DENOMINATION_INDEX = 0n;

const AVAX_FUND_AMOUNT = ethers.parseEther("0.1"); // AVAX to send each new wallet for gas
const MIN_AVAX         = ethers.parseEther("0.05");

const MULTI_DATA_FILE = path.join(__dirname, "fuji-intents-all.json");
const INFO_FILE       = path.join(__dirname, "../../../info.md");

// ── BabyJubJub key helpers ────────────────────────────────────────────────────

function loadOrCreateKey(address: string) {
    const keyFile = path.join(__dirname, `fuji-key-${address.toLowerCase()}.json`);
    if (fs.existsSync(keyFile)) {
        const raw = JSON.parse(fs.readFileSync(keyFile, "utf8"));
        return {
            privateKey:          BigInt(raw.privateKey),
            formattedPrivateKey: BigInt(raw.formattedPrivateKey),
            publicKey:           raw.publicKey.map(BigInt) as [bigint, bigint],
        };
    }
    const privateKey          = genPrivKey();
    const formattedPrivateKey = formatPrivKeyForBabyJub(privateKey) % subOrder;
    const publicKey           = mulPointEscalar(Base8, formattedPrivateKey).map(BigInt) as [bigint, bigint];
    fs.writeFileSync(keyFile, JSON.stringify({
        privateKey:          privateKey.toString(),
        formattedPrivateKey: formattedPrivateKey.toString(),
        publicKey:           publicKey.map(String),
    }, null, 2));
    console.log("  New BabyJubJub key saved to", path.basename(keyFile));
    return { privateKey, formattedPrivateKey, publicKey };
}

function genRegistrationHash(chainId: bigint, formattedPrivateKey: bigint, address: string): bigint {
    return poseidon3([chainId, formattedPrivateKey, BigInt(address)]);
}

// ── Per-wallet bootstrap ──────────────────────────────────────────────────────

async function bootstrapWallet(
    signer: ethers.Signer,
    funder: ethers.Signer,
    chainId: bigint,
    registrar: any,
    encryptedERC: any,
    erc20: any,
): Promise<{
    intentHash:     string;
    tokenId:        string;
    destination:    string;
    amount:         string;
    nonce:          string;
    proof:          any;
    userBalancePCT: string[];
    intentMetadata: string;
    submitTimestamp: number;
    executeAfter:   number;
}> {
    const address = await signer.getAddress();
    console.log(`\n── Wallet: ${address} ──`);

    // ── Fund AVAX if needed ──
    const avaxBal = await ethers.provider.getBalance(address);
    if (avaxBal < MIN_AVAX) {
        console.log(`  AVAX low (${ethers.formatEther(avaxBal)}). Funding...`);
        const fundTx = await funder.sendTransaction({ to: address, value: AVAX_FUND_AMOUNT });
        await fundTx.wait();
        console.log("  Funded with 0.1 AVAX. tx:", fundTx.hash);
    } else {
        console.log(`  AVAX: ${ethers.formatEther(avaxBal)}`);
    }

    // ── Fund TEST if needed ──
    const testBal = await erc20.balanceOf(address);
    if (testBal < DEPOSIT_AMOUNT) {
        const needed = DEPOSIT_AMOUNT - testBal;
        console.log(`  TEST low (${ethers.formatEther(testBal)}). Transferring ${ethers.formatEther(needed)} TEST...`);
        const transferTx = await erc20.connect(funder).transfer(address, needed);
        await transferTx.wait();
        console.log("  Transferred TEST. tx:", transferTx.hash);
    } else {
        console.log(`  TEST: ${ethers.formatEther(testBal)}`);
    }

    // ── BabyJubJub key ──
    const { privateKey, formattedPrivateKey, publicKey } = loadOrCreateKey(address);

    // ── Step 1: Register ──
    const alreadyRegistered = await registrar.isUserRegistered(address);
    if (alreadyRegistered) {
        console.log("  [1] Already registered.");
    } else {
        console.log("  [1] Registering...");
        const registrationCircuit = await zkit.getCircuit("RegistrationCircuit");
        const registrationHash    = genRegistrationHash(chainId, formattedPrivateKey, address);
        const proof    = await (registrationCircuit as unknown as RegistrationCircuit).generateProof({
            SenderPrivateKey:  formattedPrivateKey,
            SenderPublicKey:   publicKey,
            SenderAddress:     BigInt(address),
            ChainID:           chainId,
            RegistrationHash:  registrationHash,
        });
        const calldata = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proof);
        const tx = await registrar.connect(signer).register({
            proofPoints:   calldata.proofPoints,
            publicSignals: calldata.publicSignals,
        });
        await tx.wait();
        console.log("  [1] Registered. tx:", tx.hash);
    }

    // ── Step 2: Deposit ──
    let tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
    const existingBalance = tokenId > 0n
        ? await encryptedERC.balanceOf(address, tokenId)
        : null;
    const alreadyDeposited = existingBalance && existingBalance.amountPCTs.length > 0;

    if (alreadyDeposited) {
        console.log("  [2] Already deposited. tokenId:", tokenId.toString());
    } else {
        const allowance = await erc20.allowance(address, CONTRACTS.encryptedERC);
        if (allowance < DEPOSIT_AMOUNT) {
            const approveTx = await erc20.connect(signer).approve(CONTRACTS.encryptedERC, DEPOSIT_AMOUNT);
            await approveTx.wait();
        }
        const { ciphertext: ct, nonce: ptNonce, authKey } = processPoseidonEncryption([DEPOSIT_AMOUNT], publicKey);
        const depositTx = await (encryptedERC.connect(signer) as any)["deposit(uint256,address,uint256[7])"](
            DEPOSIT_AMOUNT, CONTRACTS.erc20, [...ct, ...authKey, ptNonce],
        );
        await depositTx.wait();
        tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
        console.log("  [2] Deposited 100 TEST. tokenId:", tokenId.toString(), "tx:", depositTx.hash);
    }

    // ── Step 3: Denominations (only owner can set, skip if already set) ──
    const existingDenoms = await encryptedERC.getDenominations(tokenId);
    if (existingDenoms.length === 0) {
        // Only the deployer/owner can call this — skip here (bootstrap-main handles it)
        console.log("  [3] WARNING: denominations not set. Run as owner first.");
    } else {
        console.log("  [3] Denominations already set.");
    }

    // ── Step 4: Submit withdraw intent ──
    const hasPendingIntent = await (encryptedERC as any).pendingIntents(address, tokenId);
    if (hasPendingIntent) {
        console.log("  [4] Pending intent already exists — skipping.");
        throw new Error(`Wallet ${address} already has a pending intent but no data to recover. Cancel it first.`);
    }

    const balance = await encryptedERC.balanceOf(address, tokenId);
    const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];

    const auditorPubKeyRaw = await encryptedERC.auditorPublicKey();
    const auditorPublicKey: bigint[] = [auditorPubKeyRaw[0], auditorPubKeyRaw[1]];

    const userForHelper = {
        privateKey, formattedPrivateKey, publicKey,
        signer, address: BigInt(address),
        genRegistrationHash: (cid: bigint) => genRegistrationHash(cid, formattedPrivateKey, address),
        getAddress: () => address,
    } as any;

    console.log("  [4] Generating ZK proof...");
    const { proof: intentCalldata, userBalancePCT, intentHash } = await withdrawIntent(
        INTERNAL_AMOUNT,
        address,
        tokenId,
        NONCE,
        userForHelper,
        userEncryptedBalance,
        INTERNAL_AMOUNT,
        auditorPublicKey,
    );

    const encryptedMeta = encryptMetadata(publicKey, `Avacado Fuji batch test — ${address}`);

    const submitTx = await encryptedERC.connect(signer).submitWithdrawIntent(
        tokenId, DENOMINATION_INDEX, BATCH_WINDOW_INDEX,
        intentCalldata, userBalancePCT, encryptedMeta,
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
    console.log("  [4] Intent submitted. tx:", submitTx.hash);
    console.log("       intentHash:", onChainIntentHash);
    console.log("       execute after:", new Date(executeAfter * 1000).toISOString());

    const serialize = (v: any): any => {
        if (typeof v === "bigint") return v.toString();
        if (Array.isArray(v)) return v.map(serialize);
        if (typeof v === "object" && v !== null)
            return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, serialize(val)]));
        return v;
    };

    return {
        intentHash:      onChainIntentHash,
        tokenId:         tokenId.toString(),
        destination:     address,
        amount:          INTERNAL_AMOUNT.toString(),
        nonce:           NONCE.toString(),
        proof:           serialize(intentCalldata),
        userBalancePCT:  userBalancePCT.map(String),
        intentMetadata:  encryptedMeta,
        submitTimestamp,
        executeAfter,
    };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    console.log("\n=== Avacado Fuji Multi-Wallet Bootstrap ===\n");

    if (!process.env.WALLET_KEY_2 || !process.env.WALLET_KEY_3) {
        throw new Error("WALLET_KEY_2 and WALLET_KEY_3 must be set in .env");
    }

    const provider = ethers.provider;
    const deployer = (await ethers.getSigners())[0];
    console.log("Funder (deployer):", deployer.address);
    console.log("AVAX balance:", ethers.formatEther(await provider.getBalance(deployer.address)));

    const wallet2 = new ethers.Wallet(process.env.WALLET_KEY_2, provider);
    const wallet3 = new ethers.Wallet(process.env.WALLET_KEY_3, provider);

    const network = await provider.getNetwork();
    const chainId = BigInt(network.chainId);
    console.log("Chain ID:", chainId.toString());

    const registrar    = await ethers.getContractAt("Registrar",    CONTRACTS.registrar,    deployer);
    const encryptedERC = await ethers.getContractAt("EncryptedERC", CONTRACTS.encryptedERC, deployer);
    const erc20        = await ethers.getContractAt("SimpleERC20",  CONTRACTS.erc20,        deployer);

    // Load existing intent from wallet 1 (deployer) if it exists
    const existingIntents: any[] = [];
    if (fs.existsSync(path.join(__dirname, "fuji-intent-data.json"))) {
        const raw  = JSON.parse(fs.readFileSync(path.join(__dirname, "fuji-intent-data.json"), "utf8"));
        existingIntents.push(raw);
        console.log("\n[Wallet 1] Intent already submitted:", raw.intentHash);
    } else {
        console.log("\n[Wallet 1] No existing intent — run fuji-bootstrap.ts first.");
    }

    // Bootstrap wallet 2
    const intent2 = await bootstrapWallet(wallet2, deployer, chainId, registrar, encryptedERC, erc20);

    // Bootstrap wallet 3
    const intent3 = await bootstrapWallet(wallet3, deployer, chainId, registrar, encryptedERC, erc20);

    // Combine all intents
    const allIntents = [...existingIntents, intent2, intent3];
    const latestExecuteAfter = Math.max(...allIntents.map((i: any) => i.executeAfter ?? 0));

    const multiData = {
        contracts:     CONTRACTS,
        executeAfter:  latestExecuteAfter,
        intents:       allIntents,
    };

    fs.writeFileSync(MULTI_DATA_FILE, JSON.stringify(multiData, null, 2));
    console.log("\n\nAll intent data saved to fuji-intents-all.json");

    // Update info.md
    const infoMd = `# Fuji Multi-Wallet Batch Test

## Status

${allIntents.length} intents submitted. Earliest executable after:
**${new Date(latestExecuteAfter * 1000).toUTCString()}**

## Intents

| # | Wallet | intentHash | executeAfter |
|---|---|---|---|
${allIntents.map((d: any, i: number) => `| ${i + 1} | \`${d.destination}\` | \`${d.intentHash?.slice(0, 18)}...\` | ${new Date((d.executeAfter ?? 0) * 1000).toUTCString()} |`).join("\n")}

## How to Execute

\`\`\`bash
cd TrulyEncryptedERC
npx hardhat run scripts/fuji-execute-batch-multi.ts --network fuji
\`\`\`

## Contract Addresses

| Contract | Address |
|---|---|
| EncryptedERC | \`${CONTRACTS.encryptedERC}\` |
| Registrar | \`${CONTRACTS.registrar}\` |
| TEST token | \`${CONTRACTS.erc20}\` |
`;

    fs.writeFileSync(INFO_FILE, infoMd);
    console.log("info.md updated.");

    console.log(`\n=== Done. Execute after: ${new Date(latestExecuteAfter * 1000).toISOString()} ===`);
    console.log("Run: npx hardhat run scripts/fuji-execute-batch-multi.ts --network fuji\n");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
