import { ethers } from "hardhat";
import type { RegistrationCircuit } from "../generated-types/zkit";
import { zkit } from "hardhat";
import {
	encryptMetadata,
	processPoseidonEncryption,
} from "../src";
import {
	getDecryptedBalance,
	withdrawIntent,
} from "../test/helpers";
import { User } from "../test/user";
import dotenv from "dotenv";

dotenv.config();

// Deployed contract addresses on Fuji
const CONTRACTS = {
	registrar: "0xe3e9F5B05ED3cD1b9d7B67607276C8f333e16408",
	encryptedERC: "0x1E8617263656B945087bC4bEaaB530Af6fD844dD",
	erc20: "0xA4DeF71A5848768e4E33256aFfc2E83733DE424a",
};

const DECIMALS = 18;

async function main() {
	console.log("\n=== Fuji Testnet - Time-Based Permission Verification ===\n");

	// Get wallets from environment variables
	const deployerWallet = new ethers.Wallet(process.env.PRIVATE_KEY!, ethers.provider);
	const auditorWallet = new ethers.Wallet(process.env.AUDITOR_PRIVATE_KEY!, ethers.provider);
	const relayerWallet = new ethers.Wallet(process.env.RELAYER_PRIVATE_KEY!, ethers.provider);

	console.log("Accounts:");
	console.log(`  Deployer/User: ${deployerWallet.address}`);
	console.log(`  Auditor: ${auditorWallet.address}`);
	console.log(`  Relayer: ${relayerWallet.address}`);

	// Create User objects with separate wallets
	const user1 = new User(deployerWallet);
	const auditor = new User(auditorWallet);

	// Get contract instances
	const registrar = await ethers.getContractAt("Registrar", CONTRACTS.registrar);
	const encryptedERC = await ethers.getContractAt("EncryptedERC", CONTRACTS.encryptedERC);
	const erc20 = await ethers.getContractAt("SimpleERC20", CONTRACTS.erc20);

	console.log("\n=== Step 1: Register Users ===");

	const network = await ethers.provider.getNetwork();
	const chainId = BigInt(network.chainId);
	console.log(`Chain ID: ${chainId}`);

	const registrationCircuit = await zkit.getCircuit("RegistrationCircuit");

	// Register user1
	const registrationHash1 = user1.genRegistrationHash(chainId);
	const input1 = {
		SenderPrivateKey: user1.formattedPrivateKey,
		SenderPublicKey: user1.publicKey,
		SenderAddress: BigInt(user1.signer.address),
		ChainID: chainId,
		RegistrationHash: registrationHash1,
	};

	const proof1 = await (registrationCircuit as unknown as RegistrationCircuit).generateProof(input1);
	const calldata1 = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proof1);

	const registerTx1 = await registrar.connect(user1.signer).register({
		proofPoints: calldata1.proofPoints,
		publicSignals: calldata1.publicSignals,
	});
	await registerTx1.wait();
	console.log(`✓ User1 registered`);

	// Register auditor
	const registrationHashAuditor = auditor.genRegistrationHash(chainId);
	const inputAuditor = {
		SenderPrivateKey: auditor.formattedPrivateKey,
		SenderPublicKey: auditor.publicKey,
		SenderAddress: BigInt(auditor.signer.address),
		ChainID: chainId,
		RegistrationHash: registrationHashAuditor,
	};

	const proofAuditor = await (registrationCircuit as unknown as RegistrationCircuit).generateProof(inputAuditor);
	const calldataAuditor = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proofAuditor);

	const registerTxAuditor = await registrar.connect(auditor.signer).register({
		proofPoints: calldataAuditor.proofPoints,
		publicSignals: calldataAuditor.publicSignals,
	});
	await registerTxAuditor.wait();
	console.log(`✓ Auditor registered`);

	console.log("\n=== Step 2: Set Auditor ===");
	const setAuditorTx = await encryptedERC.connect(deployerWallet).setAuditorPublicKey(auditor.signer.address);
	await setAuditorTx.wait();
	console.log(`✓ Auditor set`);

	console.log("\n=== Step 3: Mint ERC20 to User1 ===");
	const mintAmount = ethers.parseUnits("1000", DECIMALS);
	const mintTx = await erc20.connect(deployerWallet).mint(user1.signer.address, mintAmount);
	await mintTx.wait();
	console.log(`✓ Minted 1000 TEST tokens to User1`);

	console.log("\n=== Step 4: User1 Approves EncryptedERC ===");
	const approveTx = await erc20.connect(user1.signer).approve(encryptedERC.target, mintAmount);
	await approveTx.wait();
	console.log(`✓ Approved EncryptedERC to spend tokens`);

	console.log("\n=== Step 5: Check if User1 Already Has Balance ===");
	let tokenId = await encryptedERC.tokenIds(erc20.target);
	let balance = await encryptedERC.balanceOf(user1.signer.address, tokenId);

	let depositAmount = ethers.parseUnits("100", DECIMALS);
	let userBalance: bigint;

	if (balance.transactionIndex > 0n) {
		// User already has a balance from previous run
		console.log(`  User already has encrypted balance (transaction index: ${balance.transactionIndex})`);
		console.log(`  Skipping deposit. Will use existing balance for testing.`);

		// We can't decrypt the balance, but we can make a fresh deposit to get a known balance
		console.log(`\n  Making ADDITIONAL deposit to ensure we can generate proofs...`);
		depositAmount = ethers.parseUnits("50", DECIMALS); // Smaller amount for additional deposit

		const {
			ciphertext: depositCiphertext2,
			nonce: depositNonce2,
			authKey: depositAuthKey2,
		} = processPoseidonEncryption([depositAmount], user1.publicKey);

		const depositTx2 = await encryptedERC
			.connect(user1.signer)
			["deposit(uint256,address,uint256[7])"](
				depositAmount,
				erc20.target,
				[...depositCiphertext2, ...depositAuthKey2, depositNonce2],
			);
		await depositTx2.wait();
		console.log(`✓ Deposited additional ${ethers.formatUnits(depositAmount, DECIMALS)} TEST tokens`);

		// Now get the updated balance
		balance = await encryptedERC.balanceOf(user1.signer.address, tokenId);
	} else {
		// First deposit
		console.log(`  User has no balance yet. Making first deposit...`);
		const {
			ciphertext: depositCiphertext,
			nonce: depositNonce,
			authKey: depositAuthKey,
		} = processPoseidonEncryption([depositAmount], user1.publicKey);

		const depositTx = await encryptedERC
			.connect(user1.signer)
			["deposit(uint256,address,uint256[7])"](
				depositAmount,
				erc20.target,
				[...depositCiphertext, ...depositAuthKey, depositNonce],
			);
		await depositTx.wait();
		console.log(`✓ Deposited ${ethers.formatUnits(depositAmount, DECIMALS)} TEST tokens to EncryptedERC`);

		balance = await encryptedERC.balanceOf(user1.signer.address, tokenId);
	}

	console.log(`  Token ID: ${tokenId}`);

	console.log("\n=== Step 6: Get User1's Encrypted Balance ===");
	// Balance was already fetched and possibly updated in Step 5
	// We know the balance from the deposit amount
	userBalance = depositAmount;
	console.log(`  Known balance: ${ethers.formatUnits(userBalance, DECIMALS)} TEST (from deposit amount)`);

	console.log("\n=== Step 7: Submit Withdraw Intent ===");
	const withdrawAmount = ethers.parseUnits("50", DECIMALS);
	const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];
	const auditorPublicKey = auditor.publicKey;
	const destination = user1.signer.address;
	const nonce = 1n;

	const { proof: calldata, userBalancePCT } = await withdrawIntent(
		withdrawAmount,
		destination,
		tokenId,
		nonce,
		user1,
		userEncryptedBalance,
		userBalance,
		auditorPublicKey,
	);

	const MESSAGE = "Testing time-based permissions on Fuji";
	const encryptedMetadata = encryptMetadata(user1.publicKey, MESSAGE);

	const submitTx = await encryptedERC
		.connect(user1.signer)
		.submitWithdrawIntent(
			tokenId,
			destination,
			withdrawAmount,
			calldata,
			userBalancePCT,
			encryptedMetadata,
		);

	const submitReceipt = await submitTx.wait();
	const submitEvents = submitReceipt?.logs
		.map((log) => {
			try {
				return encryptedERC.interface.parseLog({
					topics: log.topics as string[],
					data: log.data,
				});
			} catch {
				return null;
			}
		})
		.filter((e) => e?.name === "WithdrawIntentSubmitted");

	const intentHash = submitEvents?.[0]?.args?.intentHash;
	console.log(`✓ Intent submitted`);
	console.log(`  Intent hash: ${intentHash}`);
	console.log(`  Transaction: https://testnet.snowtrace.io/tx/${submitReceipt?.hash}`);

	// Get intent details
	const intent = await encryptedERC.withdrawIntents(intentHash);
	const submitBlock = await ethers.provider.getBlock(submitReceipt?.blockNumber!);
	console.log(`  Submit time: ${new Date(Number(submitBlock?.timestamp) * 1000).toISOString()}`);
	console.log(`  Intent timestamp: ${intent.timestamp}`);

	console.log("\n=== Step 8: Try Immediate Execution by Relayer (Should FAIL) ===");
	try {
		await encryptedERC
			.connect(relayerWallet)
			.executeWithdrawIntent(
				intentHash,
				tokenId,
				destination,
				withdrawAmount,
				calldata,
				userBalancePCT,
				encryptedMetadata,
			);
		console.log("✗ UNEXPECTED: Relayer was able to execute immediately!");
	} catch (error: any) {
		if (error.message.includes("TooEarlyForRelayer")) {
			console.log("✓ CORRECT: Relayer execution blocked (too early)");
		} else {
			console.log(`✗ UNEXPECTED ERROR: ${error.message}`);
		}
	}

	console.log("\n=== Step 9: User1 Can Execute Immediately ===");
	const userExecuteTx = await encryptedERC
		.connect(user1.signer)
		.executeWithdrawIntent(
			intentHash,
			tokenId,
			destination,
			withdrawAmount,
			calldata,
			userBalancePCT,
			encryptedMetadata,
		);
	const userExecuteReceipt = await userExecuteTx.wait();
	console.log(`✓ User1 executed their own intent immediately`);
	console.log(`  Transaction: https://testnet.snowtrace.io/tx/${userExecuteReceipt?.hash}`);

	// Verify withdrawal
	const erc20Balance = await erc20.balanceOf(user1.signer.address);
	console.log(`  User1 ERC20 balance: ${ethers.formatUnits(erc20Balance, DECIMALS)} TEST`);

	console.log("\n=== VERIFICATION COMPLETE ===");
	console.log("\n📋 NEXT STEPS FOR 24-HOUR TEST:");
	console.log("1. Submit a NEW intent (this one was already executed)");
	console.log("2. Wait 24 hours (or adjust PERMISSIONLESS_DELAY in contract for testing)");
	console.log("3. Call executeWithdrawIntent with the relayer account");
	console.log("4. Verify execution succeeds\n");

	console.log("Contract addresses for reference:");
	console.table(CONTRACTS);
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
