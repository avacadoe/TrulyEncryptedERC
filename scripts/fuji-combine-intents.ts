/**
 * Combines per-wallet intent files into fuji-intents-all.json for batch execution.
 * Run after all wallets have been bootstrapped via fuji-bootstrap-single.ts.
 */
import fs from "fs";
import path from "path";

const SCRIPTS_DIR     = __dirname;
const MULTI_DATA_FILE = path.join(SCRIPTS_DIR, "fuji-intents-all.json");
const INFO_FILE       = path.join(SCRIPTS_DIR, "../../../info.md");

const WALLET_ADDRESSES = [
    "0x5185bA8Fcc613e24B6a46bEf48335F9D4389449B", // deployer (uses fuji-intent-data.json)
    "0xADDd0c80B3da1Aee010921e1d51A9f2A93e6DD6c",
    "0x6C882C81D6C78824035A8477fe29Dad7b3F600f6",
];

// Deployer uses the original fuji-intent-data.json filename
function intentFile(address: string) {
    if (address.toLowerCase() === "0x5185ba8fcc613e24b6a46bef48335f9d4389449b") {
        return path.join(SCRIPTS_DIR, "fuji-intent-data.json");
    }
    return path.join(SCRIPTS_DIR, `fuji-intent-${address.toLowerCase()}.json`);
}

const allIntents: any[] = [];
let latestExecuteAfter = 0;

for (const addr of WALLET_ADDRESSES) {
    const f = intentFile(addr);
    if (!fs.existsSync(f)) {
        console.error(`MISSING: ${path.basename(f)} — run fuji-bootstrap-single.ts for ${addr} first`);
        process.exit(1);
    }
    const data = JSON.parse(fs.readFileSync(f, "utf8"));
    allIntents.push(data);
    if ((data.executeAfter ?? 0) > latestExecuteAfter) {
        latestExecuteAfter = data.executeAfter ?? 0;
    }
    console.log(`Loaded: ${path.basename(f)} — intentHash: ${data.intentHash?.slice(0, 20)}...`);
}

const multiData = {
    contracts:    allIntents[0].contracts,
    executeAfter: latestExecuteAfter,
    intents:      allIntents,
};

fs.writeFileSync(MULTI_DATA_FILE, JSON.stringify(multiData, null, 2));
console.log(`\nWrote fuji-intents-all.json with ${allIntents.length} intents.`);
console.log(`Execute after: ${new Date(latestExecuteAfter * 1000).toISOString()}`);

// Update info.md
const infoMd = `# Fuji Multi-Wallet Batch Test

## Status

${allIntents.length} intents ready. Execute after:
**${new Date(latestExecuteAfter * 1000).toUTCString()}**

## Intents

| # | Wallet | intentHash | executeAfter |
|---|---|---|---|
${allIntents.map((d: any, i: number) => `| ${i + 1} | \`${d.destination}\` | \`${(d.intentHash ?? "").slice(0, 20)}...\` | ${new Date((d.executeAfter ?? 0) * 1000).toUTCString()} |`).join("\n")}

## How to Execute

\`\`\`bash
cd TrulyEncryptedERC
npx hardhat run scripts/fuji-execute-batch-multi.ts --network fuji
\`\`\`

## Contract

\`${allIntents[0]?.contracts?.encryptedERC ?? ""}\`
`;

fs.writeFileSync(INFO_FILE, infoMd);
console.log("info.md updated.");
