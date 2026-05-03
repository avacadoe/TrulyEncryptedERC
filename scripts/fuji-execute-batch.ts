import { ethers } from "hardhat";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

const DATA_FILE = path.join(__dirname, "fuji-intent-data.json");
const INFO_FILE = path.join(__dirname, "../../../info.md");

// ── Deserialize BigInts from JSON ─────────────────────────────────────────────
function deserialize(v: any): any {
    if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
    if (Array.isArray(v)) return v.map(deserialize);
    if (typeof v === "object" && v !== null)
        return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, deserialize(val)]));
    return v;
}

async function main() {
    console.log("\n=== Avacado Fuji — Execute Batch ===\n");

    if (!fs.existsSync(DATA_FILE)) {
        throw new Error("fuji-intent-data.json not found. Run fuji-bootstrap.ts first.");
    }

    const raw  = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    const data = deserialize(raw);

    const now = Math.floor(Date.now() / 1000);
    if (now < data.executeAfter) {
        const remaining = data.executeAfter - now;
        const hours     = Math.floor(remaining / 3600);
        const minutes   = Math.floor((remaining % 3600) / 60);
        throw new Error(
            `Too early. Batch window not expired yet.\n` +
            `Execute after: ${new Date(data.executeAfter * 1000).toISOString()}\n` +
            `Remaining: ${hours}h ${minutes}m`
        );
    }

    const [executor] = await ethers.getSigners();
    console.log("Executor:", executor.address);

    const encryptedERC = await ethers.getContractAt("EncryptedERC", data.contracts.encryptedERC, executor);
    const erc20        = await ethers.getContractAt("SimpleERC20",  data.contracts.erc20,        executor);

    // Check intent is still pending
    const intent = await encryptedERC.withdrawIntents(data.intentHash);
    if (intent.executed) throw new Error("Intent already executed.");
    if (intent.cancelled) throw new Error("Intent was cancelled.");

    console.log("Intent state: pending");
    console.log("Executing batch with single intent (intentHash:", data.intentHash, ")...");

    const erc20Before = await erc20.balanceOf(data.destination);

    const tx = await encryptedERC.executeBatchWithdrawIntents(
        [data.intentHash],
        [data.tokenId],
        [data.destination],
        [data.amount],
        [data.nonce],
        [data.proof],
        [data.userBalancePCT],
        [data.intentMetadata],
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

    const erc20After = await erc20.balanceOf(data.destination);
    const received   = erc20After - erc20Before;
    console.log("  TEST received:", ethers.formatEther(received));

    if (received === 0n) {
        console.error("\n  WARNING: No tokens received — intent may have been skipped silently.");
        console.error("  Check that the proof matches on-chain state.");
    } else {
        console.log("\n  Batch execution successful.");
    }

    // Update info.md
    const updateNote = `\n## Batch Execution Result\n\n| Field | Value |\n|---|---|\n| executor | \`${executor.address}\` |\n| tx | \`${tx.hash}\` |\n| intents executed | ${intentCount} |\n| TEST received | ${ethers.formatEther(received)} |\n| executed at | ${new Date().toUTCString()} |\n\n[View tx on Snowtrace](https://testnet.snowtrace.io/tx/${tx.hash})\n`;
    fs.appendFileSync(INFO_FILE, updateNote);
    console.log("  info.md updated.\n");

    console.log("=== Done ===");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
