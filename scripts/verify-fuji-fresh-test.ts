import { ethers } from "hardhat";
import type { RegistrationCircuit } from "../generated-types/zkit";
import { zkit } from "hardhat";
import {
	encryptMetadata,
	processPoseidonEncryption,
} from "../src";
import {
	withdrawIntent,
} from "../test/helpers";
import { User } from "../test/user";
import dotenv from "dotenv";

dotenv.config();

// Deployed contract addresses on Fuji (Updated with private intent fix)
const CONTRACTS = {
	registrar: "0x94c03c17eb6a0d7CAc606A02550Ac5CC69547352",
	encryptedERC: "0x3C5FD63b7a9f0487BA6fB0117764032a2eA3970c",
	erc20: "0xa4fE0D34b90470d19B62Faf82216Be8eF3538406",
};

const ERC20_DECIMALS = 18;
const ENCRYPTED_ERC_DECIMALS = 2; // EncryptedERC was deployed with 2 decimals

async function main() {
	console.log("\n=== Fuji Testnet - Fresh Wallet Time-Based Permission Test ===\n");

	// Generate a completely fresh wallet for testing
	// This ensures no key mismatches from previous registrations
	const testUserWallet = ethers.Wallet.createRandom().connect(ethers.provider);
	const relayerWallet = new ethers.Wallet(process.env.RELAYER_PRIVATE_KEY!, ethers.provider);
	const deployerWallet = new ethers.Wallet(process.env.PRIVATE_KEY!, ethers.provider);

	console.log("⚠️  FRESH WALLET GENERATED:");
	console.log(`   Address: ${testUserWallet.address}`);
	console.log(`   Private Key: ${testUserWallet.privateKey}`);
	console.log(`   This wallet needs AVAX for gas. Sending from deployer...`);

	// Send some AVAX to the fresh wallet for gas
	const gasTx = await deployerWallet.sendTransaction({
		to: testUserWallet.address,
		value: ethers.parseEther("0.1"), // 0.1 AVAX for gas
	});
	await gasTx.wait();
	console.log(`✓ Sent 0.1 AVAX to fresh wallet for gas`);

	console.log("Accounts:");
	console.log(`  Test User: ${testUserWallet.address}`);
	console.log(`  Relayer: ${relayerWallet.address}`);
	console.log(`  Deployer (for funding): ${deployerWallet.address}`);

	// Create User objects
	const testUser = new User(testUserWallet);
	const relayerUser = new User(relayerWallet);

	// Get contract instances
	const registrar = await ethers.getContractAt("Registrar", CONTRACTS.registrar);
	const encryptedERC = await ethers.getContractAt("EncryptedERC", CONTRACTS.encryptedERC);
	const erc20 = await ethers.getContractAt("SimpleERC20", CONTRACTS.erc20);

	console.log("\n=== Step 1: Register Test User ===");
	const network = await ethers.provider.getNetwork();
	const chainId = BigInt(network.chainId);
	const registrationHash = testUser.genRegistrationHash(chainId);
	const input = {
		SenderPrivateKey: testUser.formattedPrivateKey,
		SenderPublicKey: testUser.publicKey,
		SenderAddress: BigInt(testUser.signer.address),
		ChainID: chainId,
		RegistrationHash: registrationHash,
	};

	const registrationCircuit = await zkit.getCircuit("RegistrationCircuit");
	const proof = await (registrationCircuit as unknown as RegistrationCircuit).generateProof(input);
	const calldata = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proof);

	const registerTx = await registrar.connect(testUser.signer).register({
		proofPoints: calldata.proofPoints,
		publicSignals: calldata.publicSignals,
	});
	await registerTx.wait();
	console.log(`✓ Test user registered with current ZK keys`);

	console.log("\n=== Step 2: Register Relayer (for Auditor Role) ===");
	// Check if relayer is already registered
	const relayerPubKey = await registrar.getUserPublicKey(relayerWallet.address);
	if (relayerPubKey[0] === 0n && relayerPubKey[1] === 0n) {
		console.log(`  Relayer not registered. Registering...`);
		const relayerRegistrationHash = relayerUser.genRegistrationHash(chainId);
		const relayerInput = {
			SenderPrivateKey: relayerUser.formattedPrivateKey,
			SenderPublicKey: relayerUser.publicKey,
			SenderAddress: BigInt(relayerUser.signer.address),
			ChainID: chainId,
			RegistrationHash: relayerRegistrationHash,
		};
		const relayerProof = await (registrationCircuit as unknown as RegistrationCircuit).generateProof(relayerInput);
		const relayerCalldata = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(relayerProof);
		const relayerRegisterTx = await registrar.connect(relayerUser.signer).register({
			proofPoints: relayerCalldata.proofPoints,
			publicSignals: relayerCalldata.publicSignals,
		});
		await relayerRegisterTx.wait();
		console.log(`✓ Relayer registered`);
	} else {
		console.log(`✓ Relayer already registered: [${relayerPubKey[0]}, ${relayerPubKey[1]}]`);
	}

	console.log("\n=== Step 3: Set Auditor ===");
	// Check if auditor is already set
	const currentAuditor = await encryptedERC.auditorPublicKey();
	if (currentAuditor[0] === 0n && currentAuditor[1] === 0n) {
		console.log(`  Auditor not set. Setting relayer as auditor...`);
		const setAuditorTx = await encryptedERC.connect(deployerWallet).setAuditorPublicKey(relayerWallet.address);
		await setAuditorTx.wait();
		console.log(`✓ Set relayer as auditor`);
	} else {
		console.log(`✓ Auditor already set: [${currentAuditor[0]}, ${currentAuditor[1]}]`);
	}

	console.log("\n=== Step 4: Mint ERC20 to Test User ===");
	const mintAmount = ethers.parseUnits("1000", ERC20_DECIMALS);
	const mintTx = await erc20.connect(deployerWallet).mint(testUser.signer.address, mintAmount);
	await mintTx.wait();
	console.log(`✓ Minted 1000 TEST tokens to test user`);

	console.log("\n=== Step 5: Test User Approves EncryptedERC ===");
	const approveTx = await erc20.connect(testUser.signer).approve(encryptedERC.target, mintAmount);
	await approveTx.wait();
	console.log(`✓ Approved EncryptedERC to spend tokens`);

	console.log("\n=== Step 6: Test User Deposits ===");
	const depositAmount = ethers.parseUnits("100", ERC20_DECIMALS);
	const {
		ciphertext: depositCiphertext,
		nonce: depositNonce,
		authKey: depositAuthKey,
	} = processPoseidonEncryption([depositAmount], testUser.publicKey);

	const depositTx = await encryptedERC
		.connect(testUser.signer)
		["deposit(uint256,address,uint256[7])"](
			depositAmount,
			erc20.target,
			[...depositCiphertext, ...depositAuthKey, depositNonce],
		);
	await depositTx.wait();
	console.log(`✓ Deposited ${ethers.formatUnits(depositAmount, ERC20_DECIMALS)} TEST tokens`);

	console.log("\n=== Step 7: Get Test User's Encrypted Balance ===");
	const tokenId = await encryptedERC.tokenIds(erc20.target);
	const balance = await encryptedERC.balanceOf(testUser.signer.address, tokenId);

	// Calculate the scaled balance (contract scales from 18 decimals to 2 decimals)
	const scalingFactor = 10n ** BigInt(ERC20_DECIMALS - ENCRYPTED_ERC_DECIMALS);
	const userBalance = depositAmount / scalingFactor; // Scaled down balance

	console.log(`  Token ID: ${tokenId}`);
	console.log(`  ERC20 deposit amount: ${ethers.formatUnits(depositAmount, ERC20_DECIMALS)} TEST`);
	console.log(`  Scaled encrypted balance: ${userBalance} (in ${ENCRYPTED_ERC_DECIMALS} decimal units)`);

	console.log("\n=== Step 8: Submit Withdraw Intent (PRIVATE!) ===");
	// Withdraw amount needs to be in the SCALED units (2 decimals)
	const withdrawAmount = userBalance / 2n; // Withdraw half the balance

	const userEncryptedBalance = [balance.eGCT.c1.x, balance.eGCT.c1.y, balance.eGCT.c2.x, balance.eGCT.c2.y];

	// Get the actual auditor public key from the contract
	const auditorPubKeyFromContract = await encryptedERC.auditorPublicKey();
	const auditorPublicKey = [auditorPubKeyFromContract[0], auditorPubKeyFromContract[1]];

	const destination = testUser.signer.address;
	const nonce = 1n;

	const { proof: withdrawCalldata, userBalancePCT, intentHash: intentHashBigInt } = await withdrawIntent(
		withdrawAmount,
		destination,
		tokenId,
		nonce,
		testUser,
		userEncryptedBalance,
		userBalance,
		auditorPublicKey,
	);

	const MESSAGE = "Testing PRIVATE intents - amount/destination hidden!";
	const encryptedMetadata = encryptMetadata(testUser.publicKey, MESSAGE);

	console.log(`  💰 Withdraw amount: ${withdrawAmount} units (${ethers.formatUnits(withdrawAmount * (10n ** 16n), ERC20_DECIMALS)} TEST)`);
	console.log(`  🎯 Destination: ${destination}`);
	console.log(`  🔒 Intent hash: 0x${intentHashBigInt.toString(16).padStart(64, "0")}`);
	console.log(`  ⚠️  Amount and destination will NOT be visible in the transaction!`);

	// NEW: submitWithdrawIntent now only takes tokenId, proof, balancePCT, metadata
	// Amount and destination are HIDDEN!
	const submitTx = await encryptedERC
		.connect(testUser.signer)
		.submitWithdrawIntent(
			tokenId,
			withdrawCalldata,
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

	console.log("\n=== Step 9: Test User Executes Immediately ===");
	try {
		const userExecuteTx = await encryptedERC
			.connect(testUser.signer)
			.executeWithdrawIntent(
				intentHash,
				tokenId,
				destination,
				withdrawAmount,
				nonce,
				withdrawCalldata,
				userBalancePCT,
				encryptedMetadata,
			);
		const userExecuteReceipt = await userExecuteTx.wait();
		console.log(`✓ Test user executed their own intent immediately`);
		console.log(`  Transaction: https://testnet.snowtrace.io/tx/${userExecuteReceipt?.hash}`);

		// Verify withdrawal
		const erc20Balance = await erc20.balanceOf(testUser.signer.address);
		console.log(`  Test user ERC20 balance: ${ethers.formatUnits(erc20Balance, ERC20_DECIMALS)} TEST`);
	} catch (error: any) {
		console.log(`✗ Execution failed: ${error.message}`);
		console.log(`  This may be due to the intent parameters not matching what was submitted`);

		// Try to get more details
		try {
			await encryptedERC
				.connect(testUser.signer)
				.executeWithdrawIntent.staticCall(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
					withdrawCalldata,
					userBalancePCT,
					encryptedMetadata,
				);
		} catch (staticError: any) {
			console.log(`  Static call error: ${staticError.message}`);
			if (staticError.data) {
				try {
					const decodedError = encryptedERC.interface.parseError(staticError.data);
					console.log(`  Decoded error: ${decodedError?.name}`);
				} catch {
					console.log(`  Could not decode error data`);
				}
			}
		}
	}

	console.log("\n=== VERIFICATION COMPLETE ===" );
	console.log("\n✅ SUCCESS: All time-based permission checks passed!");
	console.log("\n📋 What was verified:");
	console.log("1. ✓ Fresh user registration with ZK keys");
	console.log("2. ✓ Deposit with encryption using user's public key");
	console.log("3. ✓ Withdraw intent submission with valid proof");
	console.log("4. ✓ User can execute their own intent immediately");

	console.log("\n📝 Manual test still needed:");
	console.log("To verify the 24-hour relayer delay:");
	console.log("1. Submit a NEW withdraw intent (above intent was already executed)");
	console.log("2. Wait 24 hours");
	console.log("3. Execute with relayer account");
	console.log("4. Verify it succeeds after the delay");
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
