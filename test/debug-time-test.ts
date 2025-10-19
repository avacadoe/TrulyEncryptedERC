import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import type { RegistrationCircuit } from "../generated-types/zkit";
import {
	decryptMetadata,
	encryptMetadata,
	processPoseidonEncryption,
} from "../src";
import {
	type SimpleERC20,
	SimpleERC20__factory,
} from "../typechain-types";
import type { EncryptedERC } from "../typechain-types/contracts/EncryptedERC";
import type { Registrar } from "../typechain-types/contracts/Registrar";
import {
	EncryptedERC__factory,
	Registrar__factory,
} from "../typechain-types/factories/contracts";
import {
	deployLibrary,
	deployVerifiers,
	getDecryptedBalance,
	withdrawIntent,
} from "./helpers";
import { User } from "./user";

const DECIMALS = 10;

describe("DEBUG: Time Advancement Investigation", () => {
	let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let encryptedERC: EncryptedERC;
	let erc20: SimpleERC20;
	let relayer: SignerWithAddress;

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];
		relayer = signers[3];

		const {
			registrationVerifier,
			mintVerifier,
			withdrawVerifier,
			withdrawIntentVerifier,
			transferVerifier,
			burnVerifier,
		} = await deployVerifiers(owner);
		const babyJubJub = await deployLibrary(owner);

		const simpleERC20Factory = new SimpleERC20__factory(owner);
		erc20 = await simpleERC20Factory
			.connect(owner)
			.deploy("Test Token", "TEST", DECIMALS);
		await erc20.waitForDeployment();

		const registrarFactory = new Registrar__factory(owner);
		const registrar_ = await registrarFactory
			.connect(owner)
			.deploy(registrationVerifier);
		await registrar_.waitForDeployment();

		const encryptedERCFactory = new EncryptedERC__factory({
			"contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
		});

		const encryptedERC_ = await encryptedERCFactory
			.connect(owner)
			.deploy({
				registrar: registrar_.target,
				isConverter: true,
				name: "Encrypted Test Token",
				symbol: "eTEST",
				decimals: DECIMALS,
				mintVerifier: mintVerifier,
				withdrawVerifier: withdrawVerifier,
				withdrawIntentVerifier: withdrawIntentVerifier,
				transferVerifier: transferVerifier,
				burnVerifier: burnVerifier,
			});
		await encryptedERC_.waitForDeployment();

		registrar = registrar_;
		encryptedERC = encryptedERC_;

		users = signers.slice(0, 3).map((signer) => new User(signer));

		const registrationCircuit = await zkit.getCircuit("RegistrationCircuit");
		const network = await ethers.provider.getNetwork();
		const chainId = BigInt(network.chainId);

		for (const user of users) {
			const registrationHash = user.genRegistrationHash(chainId);

			const input = {
				SenderPrivateKey: user.formattedPrivateKey,
				SenderPublicKey: user.publicKey,
				SenderAddress: BigInt(user.signer.address),
				ChainID: chainId,
				RegistrationHash: registrationHash,
			};

			const proof = await (
				registrationCircuit as unknown as RegistrationCircuit
			).generateProof(input);
			const calldata = await (
				registrationCircuit as unknown as RegistrationCircuit
			).generateCalldata(proof);

			const tx = await registrar.connect(user.signer).register({
				proofPoints: calldata.proofPoints,
				publicSignals: calldata.publicSignals,
			});
			await tx.wait();
		}

		await encryptedERC.connect(owner).setAuditorPublicKey(users[2].getAddress());

		const mintAmount = ethers.parseUnits("1000", DECIMALS);
		await erc20.connect(owner).mint(users[0].getAddress(), mintAmount);
		await erc20
			.connect(users[0].getSigner())
			.approve(encryptedERC.target, mintAmount);
	};

	beforeEach(async () => {
		await deployFixture();
	});

	it("DEBUG: Track blockchain state through time advancement", async () => {
		console.log("\n=== PHASE 1: Initial Setup ===");

		// Get initial block
		const block0 = await ethers.provider.getBlock("latest");
		console.log(`Initial block number: ${block0?.number}`);
		console.log(`Initial block timestamp: ${block0?.timestamp}`);

		// Deposit
		const depositAmount = ethers.parseUnits("100", DECIMALS);
		const withdrawAmount = ethers.parseUnits("50", DECIMALS);

		const {
			ciphertext: depositCiphertext,
			nonce: depositNonce,
			authKey: depositAuthKey,
		} = processPoseidonEncryption([depositAmount], users[0].publicKey);

		console.log("\n=== PHASE 2: Depositing ===");
		const depositTx = await encryptedERC
			.connect(users[0].signer)
			["deposit(uint256,address,uint256[7])"](
				depositAmount,
				erc20.target,
				[...depositCiphertext, ...depositAuthKey, depositNonce],
			);
		await depositTx.wait();

		const block1 = await ethers.provider.getBlock("latest");
		console.log(`After deposit block number: ${block1?.number}`);
		console.log(`After deposit timestamp: ${block1?.timestamp}`);

		const tokenId = await encryptedERC.tokenIds(erc20.target);
		const balance = await encryptedERC.balanceOf(
			users[0].signer.address,
			tokenId,
		);

		const userInitialBalance = await getDecryptedBalance(
			users[0].privateKey,
			balance.amountPCTs,
			balance.balancePCT,
			balance.eGCT,
		);

		console.log(`User balance: ${userInitialBalance.toString()}`);
		console.log(`Balance hash: ${ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
			["uint256", "uint256", "uint256", "uint256"],
			[balance.eGCT.c1[0], balance.eGCT.c1[1], balance.eGCT.c2[0], balance.eGCT.c2[1]]
		))}`);

		console.log("\n=== PHASE 3: Generating Proof ===");
		console.log(`User public key: ${users[0].publicKey[0]}, ${users[0].publicKey[1]}`);
		console.log(`User private key: ${users[0].privateKey.toString().substring(0, 20)}...`);

		const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];
		const auditorPublicKey = users[2].publicKey;
		const destination = users[0].signer.address;
		const nonce = 1n;

		const { proof: calldata, userBalancePCT } = await withdrawIntent(
			withdrawAmount,
			destination,
			tokenId,
			nonce,
			users[0],
			userEncryptedBalance,
			userInitialBalance,
			auditorPublicKey,
		);

		console.log(`Proof generated successfully`);
		console.log(`Public signals length: ${calldata.publicSignals.length}`);
		console.log(`First few public signals:`);
		console.log(`  [0-1] SenderPublicKey: ${calldata.publicSignals[0]}, ${calldata.publicSignals[1]}`);
		console.log(`  [2-3] SenderBalanceC1: ${calldata.publicSignals[2]}, ${calldata.publicSignals[3]}`);
		console.log(`  [4-5] SenderBalanceC2: ${calldata.publicSignals[4]}, ${calldata.publicSignals[5]}`);
		console.log(`\nVerifying proof uses user's actual public key:`);
		console.log(`  Proof PK matches: ${calldata.publicSignals[0] === users[0].publicKey[0] && calldata.publicSignals[1] === users[0].publicKey[1]}`);

		console.log("\n=== PHASE 4: Submitting Intent ===");
		const MESSAGE = "Testing time advancement";
		const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

		const submitTx = await encryptedERC
			.connect(users[0].signer)
			.submitWithdrawIntent(
				tokenId,
				calldata,
				userBalancePCT,
				encryptedMetadata,
			);

		const submitReceipt = await submitTx.wait();
		const block2 = await ethers.provider.getBlock("latest");
		console.log(`After submit block number: ${block2?.number}`);
		console.log(`After submit timestamp: ${block2?.timestamp}`);

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
		console.log(`Intent submitted with hash: ${intentHash}`);

		// Check intent storage
		const intent = await encryptedERC.withdrawIntents(intentHash);
		console.log(`Intent user: ${intent.user}`);
		console.log(`Intent timestamp: ${intent.timestamp}`);
		console.log(`Intent tokenId: ${intent.tokenId}`);

		// Check balance lock
		const isLocked = await encryptedERC.pendingIntents(users[0].signer.address, tokenId);
		console.log(`Balance locked: ${isLocked}`);

		console.log("\n=== PHASE 5: Advancing Time by 24 Hours ===");
		const timeToAdvance = 24 * 60 * 60; // 24 hours
		console.log(`Requesting time advancement of ${timeToAdvance} seconds`);

		await ethers.provider.send("evm_increaseTime", [timeToAdvance]);
		console.log(`evm_increaseTime executed`);

		await ethers.provider.send("evm_mine", []);
		console.log(`evm_mine executed`);

		// Mine one more block to ensure state is settled
		await ethers.provider.send("evm_mine", []);
		console.log(`Additional block mined`);

		const block3 = await ethers.provider.getBlock("latest");
		console.log(`After time advancement block number: ${block3?.number}`);
		console.log(`After time advancement timestamp: ${block3?.timestamp}`);
		console.log(`Time difference: ${Number(block3?.timestamp) - Number(block2?.timestamp)} seconds`);
		console.log(`Expected difference: ${timeToAdvance} seconds`);

		// Re-check balance state
		console.log("\n=== PHASE 6: Checking State After Time Advancement ===");
		const balanceAfterTime = await encryptedERC.balanceOf(
			users[0].signer.address,
			tokenId,
		);

		console.log(`Balance hash after time: ${ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
			["uint256", "uint256", "uint256", "uint256"],
			[balanceAfterTime.eGCT.c1[0], balanceAfterTime.eGCT.c1[1], balanceAfterTime.eGCT.c2[0], balanceAfterTime.eGCT.c2[1]]
		))}`);

		console.log(`Balance coordinates match: ${
			balance.eGCT.c1[0] === balanceAfterTime.eGCT.c1[0] &&
			balance.eGCT.c1[1] === balanceAfterTime.eGCT.c1[1] &&
			balance.eGCT.c2[0] === balanceAfterTime.eGCT.c2[0] &&
			balance.eGCT.c2[1] === balanceAfterTime.eGCT.c2[1]
		}`);

		const isStillLocked = await encryptedERC.pendingIntents(users[0].signer.address, tokenId);
		console.log(`Balance still locked: ${isStillLocked}`);

		const intentAfterTime = await encryptedERC.withdrawIntents(intentHash);
		console.log(`Intent still exists: ${intentAfterTime.user !== ethers.ZeroAddress}`);
		console.log(`Intent timestamp unchanged: ${intentAfterTime.timestamp === intent.timestamp}`);

		// Check balance nonce
		const balanceNonceBefore = balance.nonce;
		const balanceNonceAfter = balanceAfterTime.nonce;
		console.log(`Balance nonce before time: ${balanceNonceBefore}`);
		console.log(`Balance nonce after time: ${balanceNonceAfter}`);
		console.log(`Nonce unchanged: ${balanceNonceBefore === balanceNonceAfter}`);

		// Check transaction indices
		console.log(`Balance transaction index before: ${balance.transactionIndex}`);
		console.log(`Balance transaction index after: ${balanceAfterTime.transactionIndex}`);

		console.log("\n=== PHASE 7: Re-generating Proof After Time Advancement ===");

		// Get fresh balance after time advancement
		const balanceAfterTimeAdv = await encryptedERC.balanceOf(
			users[0].signer.address,
			tokenId,
		);

		const balanceAfterTimeAdvDecrypted = await getDecryptedBalance(
			users[0].privateKey,
			balanceAfterTimeAdv.amountPCTs,
			balanceAfterTimeAdv.balancePCT,
			balanceAfterTimeAdv.eGCT,
		);

		console.log(`Balance after time advancement: ${balanceAfterTimeAdvDecrypted}`);

		// Generate NEW proof with fresh balance data
		const userEncryptedBalanceAfterTime = [...balanceAfterTimeAdv.eGCT.c1, ...balanceAfterTimeAdv.eGCT.c2];

		const { proof: calldataAfterTime, userBalancePCT: userBalancePCTAfterTime } = await withdrawIntent(
			withdrawAmount,
			destination,
			tokenId,
			nonce,
			users[0],
			userEncryptedBalanceAfterTime,
			balanceAfterTimeAdvDecrypted,
			auditorPublicKey,
		);

		console.log(`New proof generated after time advancement`);
		console.log(`New proof coordinates match current balance: ${
			BigInt(calldataAfterTime.publicSignals[2]) === balanceAfterTimeAdv.eGCT.c1[0] &&
			BigInt(calldataAfterTime.publicSignals[3]) === balanceAfterTimeAdv.eGCT.c1[1] &&
			BigInt(calldataAfterTime.publicSignals[4]) === balanceAfterTimeAdv.eGCT.c2[0] &&
			BigInt(calldataAfterTime.publicSignals[5]) === balanceAfterTimeAdv.eGCT.c2[1]
		}`);

		console.log("\n=== PHASE 8: Attempting Execution with Fresh Proof ===");

		try {
			const executeTx = await encryptedERC
				.connect(relayer)
				.executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					calldataAfterTime,  // Use fresh proof
					userBalancePCTAfterTime,  // Use fresh balance PCT
					encryptedMetadata,
				);

			const executeReceipt = await executeTx.wait();
			console.log(`✓ Execution succeeded!`);
			console.log(`Gas used: ${executeReceipt?.gasUsed}`);

			const block4 = await ethers.provider.getBlock("latest");
			console.log(`After execution block number: ${block4?.number}`);
			console.log(`After execution timestamp: ${block4?.timestamp}`);
		} catch (error: any) {
			console.log(`✗ Execution failed!`);
			console.log(`Error: ${error.message}`);

			// Try to get more details
			if (error.message.includes("InvalidProof")) {
				console.log("\n=== Detailed Proof Validation Debugging ===");

				// Manually check what the contract will validate
				console.log(`Proof public signals being submitted:`);
				for (let i = 0; i < calldata.publicSignals.length; i++) {
					console.log(`  [${i}]: ${calldata.publicSignals[i]}`);
				}

				console.log(`\nBalance PCT being submitted:`);
				for (let i = 0; i < userBalancePCT.length; i++) {
					console.log(`  [${i}]: ${userBalancePCT[i]}`);
				}
			}

			throw error;
		}
	});
});
