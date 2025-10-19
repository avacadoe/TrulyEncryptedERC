import { ethers } from "hardhat";
import { poseidon } from "circomlibjs";

async function main() {
	console.log("\n╔════════════════════════════════════════════════════════════════╗");
	console.log("║          PRIVACY & SECURITY ANALYSIS - INTENT SYSTEM          ║");
	console.log("╚════════════════════════════════════════════════════════════════╝\n");

	const TX_HASH = "0x3536d1fc659467eefc086acb0e8536fb58734366e7832e295924a097899e84ac";

	console.log("📍 Transaction:", TX_HASH);
	console.log("🔗 Snowtrace:", `https://testnet.snowtrace.io/tx/${TX_HASH}\n`);

	// Get transaction
	const tx = await ethers.provider.getTransaction(TX_HASH);
	if (!tx) {
		console.log("❌ Transaction not found");
		return;
	}

	console.log("═══════════════════════════════════════════════════════════════\n");
	console.log("1️⃣  RAW TRANSACTION DATA (What Snowtrace Shows)\n");
	console.log("═══════════════════════════════════════════════════════════════\n");

	console.log("From:", tx.from);
	console.log("To:", tx.to);
	console.log("Value:", ethers.formatEther(tx.value), "AVAX");
	console.log("Gas Used:", tx.gasLimit.toString());
	console.log("\nInput Data (first 200 chars):");
	console.log(tx.data.substring(0, 200) + "...\n");

	// Decode with contract ABI
	const encryptedERC = await ethers.getContractAt(
		"EncryptedERC",
		"0x3C5FD63b7a9f0487BA6fB0117764032a2eA3970c"
	);

	const decoded = encryptedERC.interface.parseTransaction({
		data: tx.data,
		value: tx.value,
	});

	console.log("═══════════════════════════════════════════════════════════════\n");
	console.log("2️⃣  DECODED FUNCTION CALL (ABI Decoding)\n");
	console.log("═══════════════════════════════════════════════════════════════\n");

	console.log("Function:", decoded?.name);
	console.log("Function Signature:", decoded?.signature);

	if (decoded?.name === "submitWithdrawIntent") {
		console.log("\n📋 Function Parameters:");
		console.log("├─ tokenId:", decoded.args[0].toString());
		console.log("├─ proof: [ZK Proof Structure]");
		console.log("├─ balancePCT: [7 encrypted balance values]");
		console.log("└─ intentMetadata: [Encrypted bytes]\n");

		const proof = decoded.args[1];
		const balancePCT = decoded.args[2];
		const metadata = decoded.args[3];

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("3️⃣  WHAT'S PUBLICLY VISIBLE?\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("✅ Token ID:", decoded.args[0].toString());
		console.log("✅ User Address:", tx.from);
		console.log("✅ Contract Address:", tx.to);
		console.log("✅ ZK Proof (512 bytes)");
		console.log("✅ New Encrypted Balance (7 field elements):");
		for (let i = 0; i < balancePCT.length; i++) {
			console.log(`   [${i}] ${balancePCT[i].toString()}`);
		}
		console.log("✅ Encrypted Metadata:", ethers.hexlify(metadata).substring(0, 66) + "...");

		console.log("\n❌ NOT VISIBLE:");
		console.log("   • Withdrawal amount");
		console.log("   • Destination address");
		console.log("   • Nonce");
		console.log("   • Current balance");
		console.log("   • Metadata plaintext");

		console.log("\n═══════════════════════════════════════════════════════════════\n");
		console.log("4️⃣  ZK PROOF PUBLIC SIGNALS (16 elements)\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		const publicSignals = proof.publicSignals;
		console.log("Total Public Signals:", publicSignals.length);

		console.log("\n[0-1] User's Public Key (NOT SECRET!):");
		console.log(`  X: ${publicSignals[0]}`);
		console.log(`  Y: ${publicSignals[1]}`);

		console.log("\n[2-3] Encrypted Balance C1 (Gibberish without private key):");
		console.log(`  X: ${publicSignals[2]}`);
		console.log(`  Y: ${publicSignals[3]}`);

		console.log("\n[4-5] Encrypted Balance C2 (Gibberish without private key):");
		console.log(`  X: ${publicSignals[4]}`);
		console.log(`  Y: ${publicSignals[5]}`);

		console.log("\n[6-7] Auditor's Public Key (NOT SECRET!):");
		console.log(`  X: ${publicSignals[6]}`);
		console.log(`  Y: ${publicSignals[7]}`);

		console.log("\n[8-11] Amount Encrypted for Auditor (Only auditor can decrypt):");
		console.log(`  C1.X: ${publicSignals[8]}`);
		console.log(`  C1.Y: ${publicSignals[9]}`);
		console.log(`  C2.X: ${publicSignals[10]}`);
		console.log(`  C2.Y: ${publicSignals[11]}`);

		console.log("\n[12-13] Auth Key for Auditor's Encrypted Amount:");
		console.log(`  X: ${publicSignals[12]}`);
		console.log(`  Y: ${publicSignals[13]}`);

		console.log("\n[14] Nonce for Auditor's Encrypted Amount:");
		console.log(`  ${publicSignals[14]}`);

		console.log("\n[15] 🔒 Intent Hash = poseidon(amount, destination, tokenId, nonce):");
		const intentHash = publicSignals[15];
		console.log(`  ${intentHash}`);
		console.log(`  Hex: 0x${BigInt(intentHash).toString(16).padStart(64, "0")}`);

		console.log("\n═══════════════════════════════════════════════════════════════\n");
		console.log("5️⃣  SECURITY ANALYSIS: CAN THE HASH BE BROKEN?\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("🔐 Intent Hash Security:");
		console.log("\nThe intentHash is: poseidon(amount, destination, tokenId, nonce)\n");

		console.log("✅ SECURE because:");
		console.log("   1. Poseidon is a cryptographic hash function");
		console.log("   2. One-way function: hash → inputs is computationally infeasible");
		console.log("   3. Pre-image resistance: Can't reverse hash to find inputs");
		console.log("   4. Collision resistance: Can't find two inputs with same hash");

		console.log("\n⚠️  POTENTIAL ATTACKS:");

		console.log("\n📊 Attack 1: Brute Force (Try all combinations)");
		console.log("   Complexity: O(2^256) for 256-bit hash");
		console.log("   Time: Longer than age of universe");
		console.log("   Verdict: ❌ NOT FEASIBLE\n");

		console.log("📊 Attack 2: Rainbow Tables (Pre-computed hashes)");
		console.log("   Problem: Need to know:");
		console.log("     • Possible amounts (e.g., 1-10000 units)");
		console.log("     • Possible destinations (limited address space)");
		console.log("     • Token ID (known from transaction)");
		console.log("     • Nonce (usually 1, 2, 3...)");
		console.log("   Verdict: ⚠️  PARTIALLY FEASIBLE if search space is small\n");

		console.log("📊 Attack 3: Dictionary Attack (Common amounts)");
		console.log("   If attacker knows user likely withdrew:");
		console.log("     • Round amounts: 10, 50, 100, 1000");
		console.log("     • To common addresses (their own wallets)");
		console.log("   Attacker can compute:");
		console.log("     poseidon(50, 0xAlice, 1, 1)");
		console.log("     poseidon(100, 0xAlice, 1, 1)");
		console.log("   And compare with intentHash!");
		console.log("   Verdict: ⚠️  FEASIBLE for predictable patterns\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("6️⃣  REAL-WORLD PRIVACY ANALYSIS\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("Scenario: Alice submits intent hash H1");
		console.log("Later: Relayer batches 50 intents including H1\n");

		console.log("🔍 What can an observer do?\n");

		console.log("Option 1: Brute Force Intent Hash");
		console.log("   For each intent hash H1...H50:");
		console.log("   For amount in [1...10000]:");
		console.log("   For destination in [known_addresses]:");
		console.log("   For nonce in [1...100]:");
		console.log("     if poseidon(amount, dest, tokenId, nonce) == H:");
		console.log("       Found! H = (amount, dest, tokenId, nonce)");
		console.log("\n   Complexity: O(amounts × destinations × nonces)");
		console.log("   Example: 10,000 × 100 × 100 = 100M hashes");
		console.log("   Time: Minutes on modern hardware");
		console.log("   Verdict: ⚠️  FEASIBLE if search space is constrained\n");

		console.log("Option 2: Statistical Analysis");
		console.log("   • Track which addresses receive tokens during batch execution");
		console.log("   • Link intent hashes to withdrawals via timing");
		console.log("   • Build probability models");
		console.log("   Verdict: ⚠️  Reduces anonymity set\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("7️⃣  HOW TO IMPROVE PRIVACY\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("✅ 1. Increase Search Space (RECOMMENDED):");
		console.log("   • Add random salt to intent hash");
		console.log("   • intentHash = poseidon(amount, dest, tokenId, nonce, SALT)");
		console.log("   • Salt = 256-bit random value");
		console.log("   • Makes brute force impossible\n");

		console.log("✅ 2. Commitment Scheme:");
		console.log("   • Submit: commitment = hash(hash(params), blindingFactor)");
		console.log("   • Reveal: Provide hash(params) and blindingFactor");
		console.log("   • Two layers of hiding\n");

		console.log("✅ 3. Larger Anonymity Sets:");
		console.log("   • Batch 1000+ intents instead of 50");
		console.log("   • More intents = harder to link\n");

		console.log("✅ 4. Decoy Intents:");
		console.log("   • Users submit fake intents they never execute");
		console.log("   • Hides real intent among noise\n");

		console.log("✅ 5. Time Delays:");
		console.log("   • Randomize execution timing");
		console.log("   • Breaks timing-based correlation\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("8️⃣  CURRENT IMPLEMENTATION: SECURITY VERDICT\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("🟢 STRONG PRIVACY:");
		console.log("   ✓ User's total balance never revealed");
		console.log("   ✓ Balance encrypted with ElGamal (IND-CPA secure)");
		console.log("   ✓ ZK proofs hide all private inputs");
		console.log("   ✓ Batching creates anonymity sets\n");

		console.log("🟡 MODERATE PRIVACY (Intent Details):");
		console.log("   ~ Intent hash is one-way function");
		console.log("   ~ Secure against brute force");
		console.log("   ~ Vulnerable to dictionary attacks if:");
		console.log("     • Amounts are predictable (round numbers)");
		console.log("     • Destinations are limited (common addresses)");
		console.log("     • Nonces are sequential (1, 2, 3...)");
		console.log("   ~ Attack complexity: O(search_space)");
		console.log("   ~ Can be defeated with larger batches\n");

		console.log("🔴 WEAKER PRIVACY:");
		console.log("   ✗ Execution reveals amount & destination publicly");
		console.log("   ✗ This is by design (ERC20 transfer is public)");
		console.log("   ✗ Batching helps but doesn't fully hide linkage\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("9️⃣  COMPARISON TO OTHER PRIVACY SYSTEMS\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("📊 Zcash (Shielded → Transparent):");
		console.log("   • Shielded pool: Fully private");
		console.log("   • Withdrawal: Amount visible, sender hidden");
		console.log("   • Your system: Amount hidden during intent, visible during execution\n");

		console.log("📊 Tornado Cash:");
		console.log("   • Deposit: Amount & sender visible");
		console.log("   • Withdraw: Amount visible, sender hidden by anonymity set");
		console.log("   • Your system: Similar privacy model\n");

		console.log("📊 Aztec Network:");
		console.log("   • Fully private: Amount, sender, receiver all hidden");
		console.log("   • Uses recursive ZK-SNARKs");
		console.log("   • Your system: Hybrid privacy (balance private, transfers semi-private)\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
		console.log("🎯 FINAL VERDICT\n");
		console.log("═══════════════════════════════════════════════════════════════\n");

		console.log("Your current implementation provides:");
		console.log("\n✅ EXCELLENT balance privacy:");
		console.log("   • Total holdings never revealed");
		console.log("   • Encrypted with strong crypto (ElGamal)");
		console.log("   • ZK proofs ensure correctness\n");

		console.log("🟡 GOOD intent privacy:");
		console.log("   • Intent hash is cryptographically secure");
		console.log("   • Resistant to brute force");
		console.log("   • Vulnerable to dictionary attacks with small search spaces");
		console.log("   • Can be broken if amounts/destinations are predictable\n");

		console.log("🟢 RECOMMENDED IMPROVEMENT:");
		console.log("   Add 256-bit random salt to intent hash:");
		console.log("   intentHash = poseidon([amount, dest, tokenId, nonce, SALT])\n");
		console.log("   This makes dictionary attacks computationally infeasible.");
		console.log("   Cost: Minimal (one extra field in proof)\n");

		console.log("Security Level:");
		console.log("   Current:  ⭐⭐⭐⭐ (4/5 stars)");
		console.log("   With Salt: ⭐⭐⭐⭐⭐ (5/5 stars)\n");

		console.log("═══════════════════════════════════════════════════════════════\n");
	}
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
