/**
 * Single-wallet bootstrap. Process ONE wallet per process invocation to avoid
 * WASM memory corruption when generating multiple ZK proofs in sequence.
 *
 * Usage:
 *   TARGET_KEY=<0xPRIVATE_KEY> npx hardhat run scripts/fuji-bootstrap-single.ts --network fuji
 *
 * Output: appends/updates scripts/fuji-intent-<address>.json
 */
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

const CONTRACTS = {
    registrar:    "0xe2d281288637CF6164986793C52C32928A74ec57",
    encryptedERC: "0x69c975f94aaA927906c29b16a09eDA25A1Da4E7C",
    erc20:        "0xFC3b7551Af3a5Dd802229223069c134ad543895D",
};

const ERC20_DECIMALS    = 18;
const CONTRACT_DECIMALS = 2;
const SCALING_FACTOR    = 10n ** BigInt(ERC20_DECIMALS - CONTRACT_DECIMALS);
const DEPOSIT_AMOUNT    = ethers.parseEther("100");
const INTERNAL_AMOUNT   = DEPOSIT_AMOUNT / SCALING_FACTOR; // 10000
const DENOMINATION      = ethers.parseEther("100");
const NONCE             = 1n;
const BATCH_WINDOW_IDX  = 0n;
const DENOM_IDX         = 0n;

const MIN_AVAX       = ethers.parseEther("0.05");
const FUND_AVAX      = ethers.parseEther("0.1");

function keyFile(address: string) {
    return path.join(__dirname, `fuji-key-${address.toLowerCase()}.json`);
}

function intentFile(address: string) {
    return path.join(__dirname, `fuji-intent-${address.toLowerCase()}.json`);
}

function loadOrCreateKey(address: string) {
    const f = keyFile(address);
    if (fs.existsSync(f)) {
        const raw = JSON.parse(fs.readFileSync(f, "utf8"));
        return {
            privateKey:          BigInt(raw.privateKey),
            formattedPrivateKey: BigInt(raw.formattedPrivateKey),
            publicKey:           raw.publicKey.map(BigInt) as [bigint, bigint],
        };
    }
    const privateKey          = genPrivKey();
    const formattedPrivateKey = formatPrivKeyForBabyJub(privateKey) % subOrder;
    const publicKey           = mulPointEscalar(Base8, formattedPrivateKey).map(BigInt) as [bigint, bigint];
    fs.writeFileSync(f, JSON.stringify({
        privateKey:          privateKey.toString(),
        formattedPrivateKey: formattedPrivateKey.toString(),
        publicKey:           publicKey.map(String),
    }, null, 2));
    console.log("  New BabyJubJub key saved:", path.basename(f));
    return { privateKey, formattedPrivateKey, publicKey };
}

function genRegistrationHash(chainId: bigint, fpk: bigint, address: string) {
    return poseidon3([chainId, fpk, BigInt(address)]);
}

async function main() {
    const targetKey = process.env.TARGET_KEY;
    if (!targetKey) throw new Error("TARGET_KEY env var required");

    const provider = ethers.provider;
    const deployer = (await ethers.getSigners())[0];
    const signer   = new ethers.Wallet(targetKey, provider);
    const address  = await signer.getAddress();

    console.log(`\n=== Fuji Bootstrap: ${address} ===\n`);
    console.log("Funder:", deployer.address, `(${ethers.formatEther(await provider.getBalance(deployer.address))} AVAX)`);

    const registrar    = await ethers.getContractAt("Registrar",    CONTRACTS.registrar,    deployer);
    const encryptedERC = await ethers.getContractAt("EncryptedERC", CONTRACTS.encryptedERC, deployer);
    const erc20        = await ethers.getContractAt("SimpleERC20",  CONTRACTS.erc20,        deployer);

    const network = await provider.getNetwork();
    const chainId = BigInt(network.chainId);

    // ── Fund AVAX ──
    const avaxBal = await provider.getBalance(address);
    if (avaxBal < MIN_AVAX) {
        console.log(`[Fund] AVAX low (${ethers.formatEther(avaxBal)}). Sending 0.1 AVAX...`);
        const tx = await deployer.sendTransaction({ to: address, value: FUND_AVAX });
        await tx.wait();
        console.log("  tx:", tx.hash);
    } else {
        console.log(`[Fund] AVAX: ${ethers.formatEther(avaxBal)} — OK`);
    }

    // ── Fund TEST ──
    const testBal = await erc20.balanceOf(address);
    if (testBal < DEPOSIT_AMOUNT) {
        const needed = DEPOSIT_AMOUNT - testBal;
        console.log(`[Fund] Sending ${ethers.formatEther(needed)} TEST...`);
        const tx = await erc20.connect(deployer).transfer(address, needed);
        await tx.wait();
        console.log("  tx:", tx.hash);
    } else {
        console.log(`[Fund] TEST: ${ethers.formatEther(testBal)} — OK`);
    }

    // ── BabyJubJub key ──
    const { privateKey, formattedPrivateKey, publicKey } = loadOrCreateKey(address);

    // ── Step 1: Register ──
    const alreadyRegistered = await registrar.isUserRegistered(address);
    if (alreadyRegistered) {
        console.log("[1] Already registered.");
    } else {
        console.log("[1] Registering...");
        const circuit = await zkit.getCircuit("RegistrationCircuit");
        const regHash = genRegistrationHash(chainId, formattedPrivateKey, address);
        const proof   = await (circuit as unknown as RegistrationCircuit).generateProof({
            SenderPrivateKey: formattedPrivateKey,
            SenderPublicKey:  publicKey,
            SenderAddress:    BigInt(address),
            ChainID:          chainId,
            RegistrationHash: regHash,
        });
        const calldata = await (circuit as unknown as RegistrationCircuit).generateCalldata(proof);
        const tx = await registrar.connect(signer).register({
            proofPoints:   calldata.proofPoints,
            publicSignals: calldata.publicSignals,
        });
        await tx.wait();
        console.log("[1] Registered. tx:", tx.hash);
    }

    // ── Step 2: Deposit ──
    let tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
    const existingBal = tokenId > 0n ? await encryptedERC.balanceOf(address, tokenId) : null;
    const deposited   = existingBal && existingBal.amountPCTs.length > 0;

    if (deposited) {
        console.log("[2] Already deposited. tokenId:", tokenId.toString());
    } else {
        const allowance = await erc20.allowance(address, CONTRACTS.encryptedERC);
        if (allowance < DEPOSIT_AMOUNT) {
            const tx = await erc20.connect(signer).approve(CONTRACTS.encryptedERC, DEPOSIT_AMOUNT);
            await tx.wait();
        }
        const { ciphertext: ct, nonce: ptN, authKey: ak } = processPoseidonEncryption([DEPOSIT_AMOUNT], publicKey);
        const tx = await (encryptedERC.connect(signer) as any)["deposit(uint256,address,uint256[7])"](
            DEPOSIT_AMOUNT, CONTRACTS.erc20, [...ct, ...ak, ptN],
        );
        await tx.wait();
        tokenId = await encryptedERC.tokenIds(CONTRACTS.erc20);
        console.log("[2] Deposited 100 TEST. tokenId:", tokenId.toString(), "tx:", tx.hash);
    }

    // ── Step 3: Denominations (owner only — skip, deployer handled this) ──
    const denoms = await encryptedERC.getDenominations(tokenId);
    if (denoms.length === 0) {
        console.log("[3] Setting denominations (requires owner)...");
        const tx = await encryptedERC.connect(deployer).setDenominations(tokenId, [DENOMINATION]);
        await tx.wait();
        console.log("[3] Done. tx:", tx.hash);
    } else {
        console.log("[3] Denominations OK.");
    }

    // ── Step 4: Submit withdraw intent ──
    const hasPending = await (encryptedERC as any).pendingIntents(address, tokenId);

    // Load intent file if it already exists (proof already generated)
    const iFile = intentFile(address);
    if (hasPending && fs.existsSync(iFile)) {
        console.log("[4] Pending intent exists and data file found — nothing to do.");
        console.log("    Intent file:", path.basename(iFile));
        return;
    }

    if (hasPending) {
        // Intent is on-chain but we lost the proof — regenerate proof with same inputs
        console.log("[4] Pending intent on-chain but no local data. Regenerating proof...");
    } else {
        console.log("[4] Generating proof and submitting intent...");
    }

    const balance             = await encryptedERC.balanceOf(address, tokenId);
    const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];
    const auditorPubKeyRaw    = await encryptedERC.auditorPublicKey();
    const auditorPublicKey    = [auditorPubKeyRaw[0], auditorPubKeyRaw[1]] as bigint[];

    const userForHelper = {
        privateKey, formattedPrivateKey, publicKey,
        signer, address: BigInt(address),
        genRegistrationHash: (cid: bigint) => genRegistrationHash(cid, formattedPrivateKey, address),
        getAddress: () => address,
    } as any;

    console.log("    Generating ZK proof (this takes ~30s)...");
    const { proof: intentCalldata, userBalancePCT, intentHash } = await withdrawIntent(
        INTERNAL_AMOUNT, address, tokenId, NONCE,
        userForHelper, userEncryptedBalance, INTERNAL_AMOUNT, auditorPublicKey,
    );

    const encryptedMeta = encryptMetadata(publicKey, `Avacado Fuji batch test — ${address}`);

    let submitTimestamp: number;
    let executeAfter: number;
    let onChainIntentHash: string;

    if (hasPending) {
        // Proof regenerated — don't re-submit, just save local data
        // Verify intentHash matches on-chain intent
        const intentHashHex  = ethers.zeroPadValue(ethers.toBeHex(intentHash), 32);
        const existingIntent = await encryptedERC.withdrawIntents(intentHashHex);
        if (existingIntent.user === ethers.ZeroAddress) {
            throw new Error(`Regenerated intentHash ${intentHashHex} not found on-chain! Inputs mismatch.`);
        }
        onChainIntentHash = intentHashHex;
        submitTimestamp   = Number(existingIntent.timestamp);
        executeAfter      = submitTimestamp + Number(existingIntent.batchWindowSeconds);
        console.log("[4] Proof regenerated. intentHash matches on-chain:", onChainIntentHash);
    } else {
        const tx = await encryptedERC.connect(signer).submitWithdrawIntent(
            tokenId, DENOM_IDX, BATCH_WINDOW_IDX, intentCalldata, userBalancePCT, encryptedMeta,
        );
        const receipt = await tx.wait();
        const block   = await provider.getBlock(receipt!.blockNumber);
        submitTimestamp = Number(block!.timestamp);
        executeAfter    = submitTimestamp + 86400;

        const events = receipt!.logs
            .map((log: any) => { try { return encryptedERC.interface.parseLog(log); } catch { return null; } })
            .filter((e: any) => e?.name === "WithdrawIntentSubmitted");
        onChainIntentHash = events[0]?.args?.intentHash;
        console.log("[4] Submitted. tx:", tx.hash);
        console.log("    intentHash:", onChainIntentHash);
        console.log("    execute after:", new Date(executeAfter * 1000).toISOString());
    }

    const serialize = (v: any): any => {
        if (typeof v === "bigint") return v.toString();
        if (Array.isArray(v)) return v.map(serialize);
        if (typeof v === "object" && v !== null)
            return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, serialize(val)]));
        return v;
    };

    const intentData = {
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
        contracts:       CONTRACTS,
    };

    fs.writeFileSync(iFile, JSON.stringify(intentData, null, 2));
    console.log("\nSaved:", path.basename(iFile));
    console.log(`=== Done: ${address} ===\n`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
