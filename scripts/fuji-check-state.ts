import { ethers } from "hardhat";
async function main() {
    const enc = await ethers.getContractAt("EncryptedERC", "0x69c975f94aaA927906c29b16a09eDA25A1Da4E7C");
    const reg = await ethers.getContractAt("Registrar",    "0xe2d281288637CF6164986793C52C32928A74ec57");
    const erc = await ethers.getContractAt("SimpleERC20",  "0xFC3b7551Af3a5Dd802229223069c134ad543895D");
    const w1 = "0x5185bA8Fcc613e24B6a46bEf48335F9D4389449B";
    const w2 = "0xADDd0c80B3da1Aee010921e1d51A9f2A93e6DD6c";
    const w3 = "0x6C882C81D6C78824035A8477fe29Dad7b3F600f6";
    for (const [label, addr] of [["W1", w1], ["W2", w2], ["W3", w3]]) {
        console.log(`\n${label} (${addr}):`);
        console.log("  registered:", await reg.isUserRegistered(addr));
        console.log("  pendingIntent(tokenId=1):", await (enc as any).pendingIntents(addr, 1n));
        console.log("  TEST balance:", ethers.formatEther(await erc.balanceOf(addr)));
    }
}
main().catch(e => { console.error(e); process.exitCode = 1; });
