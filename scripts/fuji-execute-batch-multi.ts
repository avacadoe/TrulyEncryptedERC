import { ethers } from "hardhat";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

const MULTI_DATA_FILE = path.join(__dirname, "fuji-intents-all.json");
const INFO_FILE       = path.join(__dirname, "../../../info.md");

function deserialize(v: any): any {
    if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
    if (Array.isArray(v)) return v.map(deserialize);
    if (typeof v === "object" && v !== null)
        return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, deserialize(val)]));
    return v;
}

async function main() {
    console.log("\n=== Avacado Fuji — Execute Multi-Wallet Batch ===\n");

    if (!fs.existsSync(MULTI_DATA_FILE)) {
        throw new Error("fuji-intents-all.json not found. Run fuji-bootstrap-multi.ts first.");
    }

    const raw  = JSON.parse(fs.readFileSync(MULTI_DATA_FILE, "utf8"));
    const data = deserialize(raw);

    const now = Math.floor(Date.now() / 1000);
    if (now < data.executeAfter) {
        const remaining = data.executeAfter - now;
        const hours     = Math.floor(remaining / 3600);
        const minutes   = Math.floor((remaining % 3600) / 60);
        throw new Error(
            `Too early. Latest batch window not expired yet.\n` +
            `Execute after: ${new Date(data.executeAfter * 1000).toISOString()}\n` +
            `Remaining: ${hours}h ${minutes}m`
        );
    }

    const [executor] = await ethers.getSigners();
    console.log("Executor:", executor.address);

    const encryptedERC = await ethers.getContractAt("EncryptedERC", data.contracts.encryptedERC, executor);
    const erc20        = await ethers.getContractAt("SimpleERC20",  data.contracts.erc20,        executor);

    const intents: any[] = data.intents;
    console.log(`Total intents to submit: ${intents.length}`);

    // Filter out already executed or cancelled
    const pendingIntents: any[] = [];
    for (const intent of intents) {
        const onChain = await encryptedERC.withdrawIntents(intent.intentHash);
        if (onChain.executed) {
            console.log(`  SKIP (executed): ${intent.intentHash}`);
        } else if (onChain.cancelled) {
            console.log(`  SKIP (cancelled): ${intent.intentHash}`);
        } else {
            pendingIntents.push(intent);
            console.log(`  PENDING: ${intent.intentHash} → ${intent.destination}`);
        }
    }

    if (pendingIntents.length === 0) {
        console.log("\nNo pending intents — nothing to execute.");
        return;
    }

    // Snapshot ERC20 balances before
    const balancesBefore: Record<string, bigint> = {};
    for (const intent of pendingIntents) {
        balancesBefore[intent.destination] = await erc20.balanceOf(intent.destination);
    }

    console.log(`\nExecuting batch with ${pendingIntents.length} intent(s)...`);

    const tx = await encryptedERC.executeBatchWithdrawIntents(
        pendingIntents.map((i: any) => i.intentHash),
        pendingIntents.map((i: any) => i.tokenId),
        pendingIntents.map((i: any) => i.destination),
        pendingIntents.map((i: any) => i.amount),
        pendingIntents.map((i: any) => i.nonce),
        pendingIntents.map((i: any) => i.proof),
        pendingIntents.map((i: any) => i.userBalancePCT),
        pendingIntents.map((i: any) => i.intentMetadata),
    );
    const receipt = await tx.wait();
    console.log("  tx:", tx.hash);

    const batchEvents = receipt!.logs
        .map((log: any) => {
            try { return encryptedERC.interface.parseLog({ topics: log.topics, data: log.data }); }
            catch { return null; }
        })
        .filter((e: any) => e?.name === "BatchWithdrawIntentsExecuted");

    const intentCount = batchEvents[0]?.args?.intentCount;
    console.log("  Intents executed:", intentCount?.toString());

    // Check received amounts
    let allSuccess = true;
    const rows: string[] = [];
    for (const intent of pendingIntents) {
        const after    = await erc20.balanceOf(intent.destination);
        const received = after - balancesBefore[intent.destination];
        const ok       = received > 0n;
        if (!ok) allSuccess = false;
        console.log(`  ${ok ? "✓" : "✗"} ${intent.destination}: received ${ethers.formatEther(received)} TEST`);
        rows.push(`| \`${intent.destination}\` | ${ethers.formatEther(received)} TEST |`);
    }

    if (!allSuccess) {
        console.error("\n  WARNING: Some intents may have been skipped silently.");
    } else {
        console.log("\n  Batch execution successful.");
    }

    // Update info.md
    const updateNote = `\n## Batch Execution Result\n\n| executor | \`${executor.address}\` |\n| tx | \`${tx.hash}\` |\n| intents executed | ${intentCount} |\n| executed at | ${new Date().toUTCString()} |\n\n### Withdrawals\n\n| Wallet | Received |\n|---|---|\n${rows.join("\n")}\n\n[View tx on Snowtrace](https://testnet.snowtrace.io/tx/${tx.hash})\n`;
    fs.appendFileSync(INFO_FILE, updateNote);
    console.log("  info.md updated.\n");

    console.log("=== Done ===");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
