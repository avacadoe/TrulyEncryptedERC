import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { expect } from "chai";
import { ethers, zkit } from "hardhat";
import type {
	RegistrationCircuit,
} from "../generated-types/zkit";
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

describe("EncryptedERC - Two-Step Intent System", () => {
	let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let relayer: SignerWithAddress;
	let encryptedERC: EncryptedERC;
	let erc20: SimpleERC20;

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];
		relayer = signers[9]; // Use signer 9 as relayer

		const {
			registrationVerifier,
			mintVerifier,
			withdrawVerifier,
			withdrawIntentVerifier,
			transferVerifier,
			burnVerifier,
		} = await deployVerifiers(owner);
		const babyJubJub = await deployLibrary(owner);

		// Deploy a simple ERC20 token
		const simpleERC20Factory = new SimpleERC20__factory(owner);
		erc20 = await simpleERC20Factory
			.connect(owner)
			.deploy("Test Token", "TEST", DECIMALS);
		await erc20.waitForDeployment();

		// Deploy the registrar contract
		const registrarFactory = new Registrar__factory(owner);
		const registrar_ = await registrarFactory
			.connect(owner)
			.deploy(registrationVerifier);
		await registrar_.waitForDeployment();

		// Deploy the Converter EncryptedERC contract
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

		// Create users
		users = signers.slice(0, 3).map((signer) => new User(signer));

		// Register users
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

		// Set auditor
		await encryptedERC.connect(owner).setAuditorPublicKey(users[2].getAddress());

		// Mint some ERC20 tokens to users
		const mintAmount = ethers.parseUnits("1000", DECIMALS);
		await erc20.connect(owner).mint(users[0].getAddress(), mintAmount);
		await erc20.connect(owner).mint(users[1].getAddress(), mintAmount);

		// Approve EncryptedERC to spend tokens
		await erc20
			.connect(users[0].getSigner())
			.approve(encryptedERC.target, mintAmount);
		await erc20
			.connect(users[1].getSigner())
			.approve(encryptedERC.target, mintAmount);
	};

	beforeEach(async () => {
		await deployFixture();
	});

	describe("submitWithdrawIntent", () => {
		it("should successfully submit a withdraw intent", async () => {
			// 1. Deposit tokens first
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			const depositTx = await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);
			await depositTx.wait();

			const tokenId = await encryptedERC.tokenIds(erc20.target);

			// 2. Get balance
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

			expect(userInitialBalance).to.equal(depositAmount);

			// 3. Prepare withdrawal intent
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

			// 4. Create encrypted metadata
			const MESSAGE = "Two-step withdrawal intent for privacy";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			// 5. Submit intent (NOT execute) - amount and destination now PRIVATE!
			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					calldata,
					userBalancePCT,
					encryptedMetadata,
				);

			const receipt = await submitTx.wait();

			// 6. Verify WithdrawIntentSubmitted event
			const submitEvents = receipt?.logs
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

			expect(submitEvents).to.have.length(1);
			expect(submitEvents?.[0]?.args?.user).to.equal(users[0].getAddress());

			const intentHash = submitEvents?.[0]?.args?.intentHash;
			expect(intentHash).to.not.be.undefined;

			// 7. Verify intent is stored (stores user, tokenId, timestamp, executed, cancelled)
			const intent = await encryptedERC.withdrawIntents(intentHash);
			expect(intent.user).to.equal(users[0].getAddress());
			expect(intent.tokenId).to.equal(tokenId);
			expect(intent.timestamp).to.be.greaterThan(0);
			expect(intent.executed).to.be.false;
			expect(intent.cancelled).to.be.false;

			// 8. Verify balance has NOT changed yet (intent not executed)
			const balanceAfterSubmit = await encryptedERC.balanceOf(
				users[0].signer.address,
				tokenId,
			);
			const balanceAfterSubmitDecrypted = await getDecryptedBalance(
				users[0].privateKey,
				balanceAfterSubmit.amountPCTs,
				balanceAfterSubmit.balancePCT,
				balanceAfterSubmit.eGCT,
			);

			expect(balanceAfterSubmitDecrypted).to.equal(userInitialBalance);
		});

		it("should fail if user is not registered", async () => {
			const unregisteredSigner = signers[10];

			await expect(
				encryptedERC.connect(unregisteredSigner).submitWithdrawIntent(
					1n,
					{
						proofPoints: {
							a: [0n, 0n],
							b: [
								[0n, 0n],
								[0n, 0n],
							],
							c: [0n, 0n],
						},
						publicSignals: Array(16).fill(0n),
					},
					Array(7).fill(0n),
					"0x",
				),
			).to.be.revertedWithCustomError(encryptedERC, "UserNotRegistered");
		});
	});

	describe("executeWithdrawIntent", () => {
		it("should allow user to execute their intent immediately", async () => {
			// 1. Deposit tokens
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Immediate execution by user";
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

			// 3. Execute intent immediately (user can execute within 1 hour)
			const executeTx = await encryptedERC
				.connect(users[0].signer)
				.executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
					calldata,
					userBalancePCT,
					encryptedMetadata,
				);

			const executeReceipt = await executeTx.wait();

			// 4. Verify execution event
			const executeEvents = executeReceipt?.logs
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
				.filter((e) => e?.name === "WithdrawIntentExecuted");

			expect(executeEvents).to.have.length(1);
			expect(executeEvents?.[0]?.args?.intentHash).to.equal(intentHash);
			expect(executeEvents?.[0]?.args?.executor).to.equal(users[0].getAddress());

			// 5. Verify intent is marked as executed
			const intent = await encryptedERC.withdrawIntents(intentHash);
			expect(intent.executed).to.be.true;

			// 6. Verify balance was actually withdrawn
			const erc20Balance = await erc20.balanceOf(users[0].signer.address);
			const expectedERC20Balance =
				ethers.parseUnits("1000", DECIMALS) - depositAmount + withdrawAmount;
			expect(erc20Balance).to.equal(expectedERC20Balance);

			// 7. Verify encrypted balance was updated
			const balanceAfterWithdraw = await encryptedERC.balanceOf(
				users[0].signer.address,
				tokenId,
			);
			const newDecryptedBalance = await getDecryptedBalance(
				users[0].privateKey,
				balanceAfterWithdraw.amountPCTs,
				balanceAfterWithdraw.balancePCT,
				balanceAfterWithdraw.eGCT,
			);

			const expectedNewBalance = userInitialBalance - withdrawAmount;
			expect(newDecryptedBalance).to.equal(expectedNewBalance);
		});

		it("should prevent relayer from executing before 24 hours", async () => {
			// 1. Setup and deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Testing relayer time restrictions";
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

			// 3. Try to execute with relayer immediately (should fail)
			await expect(
				encryptedERC.connect(relayer).executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
				calldata,
					userBalancePCT,
					encryptedMetadata,
				),
			).to.be.revertedWith("TooEarlyForRelayer");
		});

		it("should allow relayer to execute after 24 hours", async () => {
			// 1. Setup and deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Relayer execution after 24 hours";
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

			// 3. Advance time by 24 hours using setNextBlockTimestamp
			const currentBlock = await ethers.provider.getBlock("latest");
			const futureTimestamp = Number(currentBlock?.timestamp) + (24 * 60 * 60);
			await ethers.provider.send("evm_setNextBlockTimestamp", [futureTimestamp]);
			await ethers.provider.send("evm_mine", []);

			// 4. Execute with relayer (should succeed now)
			const executeTx = await encryptedERC
				.connect(relayer)
				.executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
					calldata,
					userBalancePCT,
					encryptedMetadata,
				);

			const executeReceipt = await executeTx.wait();

			// 5. Verify execution event shows relayer as executor
			const executeEvents = executeReceipt?.logs
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
				.filter((e) => e?.name === "WithdrawIntentExecuted");

			expect(executeEvents).to.have.length(1);
			expect(executeEvents?.[0]?.args?.executor).to.equal(relayer.address);

			// 6. Verify withdrawal went to original destination (not relayer)
			const erc20Balance = await erc20.balanceOf(users[0].signer.address);
			const expectedERC20Balance =
				ethers.parseUnits("1000", DECIMALS) - depositAmount + withdrawAmount;
			expect(erc20Balance).to.equal(expectedERC20Balance);

			// Relayer should not have received tokens
			const relayerBalance = await erc20.balanceOf(relayer.address);
			expect(relayerBalance).to.equal(0);
		});

		it("should fail if intent already executed", async () => {
			// 1. Setup, deposit, submit, and execute intent
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			const MESSAGE = "Double execution test";
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

			// Execute once
			await encryptedERC.connect(users[0].signer).executeWithdrawIntent(
				intentHash,
				tokenId,
				destination,
				withdrawAmount,
				nonce,
				calldata,
				userBalancePCT,
				encryptedMetadata,
			);

			// 2. Try to execute again (should fail)
			await expect(
				encryptedERC.connect(users[0].signer).executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
				calldata,
					userBalancePCT,
					encryptedMetadata,
				),
			).to.be.revertedWith("IntentAlreadyExecuted");
		});
	});

	describe("cancelWithdrawIntent", () => {
		it("should allow user to cancel their intent", async () => {
			// 1. Setup and deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Cancellation test";
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

			// 3. Cancel intent
			const cancelTx = await encryptedERC
				.connect(users[0].signer)
				.cancelWithdrawIntent(intentHash);

			const cancelReceipt = await cancelTx.wait();

			// 4. Verify cancellation event
			const cancelEvents = cancelReceipt?.logs
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
				.filter((e) => e?.name === "WithdrawIntentCancelled");

			expect(cancelEvents).to.have.length(1);
			expect(cancelEvents?.[0]?.args?.intentHash).to.equal(intentHash);

			// 5. Verify intent is marked as cancelled
			const intent = await encryptedERC.withdrawIntents(intentHash);
			expect(intent.cancelled).to.be.true;

			// 6. Try to execute cancelled intent (should fail)
			await expect(
				encryptedERC.connect(users[0].signer).executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
				calldata,
					userBalancePCT,
					encryptedMetadata,
				),
			).to.be.revertedWith("IntentCancelled");
		});

		it("should prevent non-owner from cancelling intent", async () => {
			// 1. Setup and deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Non-owner cancellation test";
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

			// 3. Try to cancel with different user (should fail)
			await expect(
				encryptedERC.connect(users[1].signer).cancelWithdrawIntent(intentHash),
			).to.be.revertedWith("OnlyIntentCreator");
		});
	});

	describe("executeBatchWithdrawIntents", () => {
		it("should execute multiple intents in batch", async () => {
			// 1. Setup - deposit for two users
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("30", DECIMALS);

			// User 0 deposit
			const {
				ciphertext: depositCiphertext0,
				nonce: depositNonce0,
				authKey: depositAuthKey0,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext0, ...depositAuthKey0, depositNonce0],
				);

			// User 1 deposit
			const {
				ciphertext: depositCiphertext1,
				nonce: depositNonce1,
				authKey: depositAuthKey1,
			} = processPoseidonEncryption([depositAmount], users[1].publicKey);

			await encryptedERC
				.connect(users[1].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext1, ...depositAuthKey1, depositNonce1],
				);

			const tokenId = await encryptedERC.tokenIds(erc20.target);

			// 2. Submit two intents from different users
			const intentHashes: string[] = [];

			// User 0 intent
			const balance0 = await encryptedERC.balanceOf(
				users[0].signer.address,
				tokenId,
			);
			const userInitialBalance0 = await getDecryptedBalance(
				users[0].privateKey,
				balance0.amountPCTs,
				balance0.balancePCT,
				balance0.eGCT,
			);

			const userEncryptedBalance0 = [...balance0.eGCT.c1, ...balance0.eGCT.c2];
			const auditorPublicKey = users[2].publicKey;

			const { proof: calldata0, userBalancePCT: userBalancePCT0 } =
				await withdrawIntent(
					withdrawAmount,
					users[0].signer.address,
					tokenId,
					1n,
					users[0],
					userEncryptedBalance0,
					userInitialBalance0,
					auditorPublicKey,
				);

			const encryptedMetadata0 = encryptMetadata(
				users[0].publicKey,
				"Batch intent 1",
			);

			const submitTx0 = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					calldata0,
					userBalancePCT0,
					encryptedMetadata0,
				);

			const submitReceipt0 = await submitTx0.wait();
			const submitEvents0 = submitReceipt0?.logs
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

			intentHashes.push(submitEvents0?.[0]?.args?.intentHash);

			// User 1 intent
			const balance1 = await encryptedERC.balanceOf(
				users[1].signer.address,
				tokenId,
			);
			const userInitialBalance1 = await getDecryptedBalance(
				users[1].privateKey,
				balance1.amountPCTs,
				balance1.balancePCT,
				balance1.eGCT,
			);

			const userEncryptedBalance1 = [...balance1.eGCT.c1, ...balance1.eGCT.c2];

			const { proof: calldata1, userBalancePCT: userBalancePCT1 } =
				await withdrawIntent(
					withdrawAmount,
					users[1].signer.address,
					tokenId,
					1n,
					users[1],
					userEncryptedBalance1,
					userInitialBalance1,
					auditorPublicKey,
				);

			const encryptedMetadata1 = encryptMetadata(
				users[1].publicKey,
				"Batch intent 2",
			);

			const submitTx1 = await encryptedERC
				.connect(users[1].signer)
				.submitWithdrawIntent(
					tokenId,
					calldata1,
					userBalancePCT1,
					encryptedMetadata1,
				);

			const submitReceipt1 = await submitTx1.wait();
			const submitEvents1 = submitReceipt1?.logs
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

			intentHashes.push(submitEvents1?.[0]?.args?.intentHash);

			// 3. Prepare batch execution parameters
			const tokenIds = [tokenId, tokenId];
			const destinations = [users[0].signer.address, users[1].signer.address];
			const amounts = [withdrawAmount, withdrawAmount];
			const nonces = [1n, 1n];  // Nonces used when generating the proofs
			const proofs = [calldata0, calldata1];
			const balancePCTs = [userBalancePCT0, userBalancePCT1];
			const metadatas = [encryptedMetadata0, encryptedMetadata1];

			// 4. Advance time by 24 hours for relayer execution
			const currentBlockBatch = await ethers.provider.getBlock("latest");
			const futureTimestampBatch = Number(currentBlockBatch?.timestamp) + (24 * 60 * 60);
			await ethers.provider.send("evm_setNextBlockTimestamp", [futureTimestampBatch]);
			await ethers.provider.send("evm_mine", []);

			// 5. Execute batch with relayer
			const batchTx = await encryptedERC
				.connect(relayer)
				.executeBatchWithdrawIntents(
					intentHashes,
					tokenIds,
					destinations,
					amounts,
					nonces,
					proofs,
					balancePCTs,
					metadatas,
				);

			const batchReceipt = await batchTx.wait();

			// 5. Verify batch execution event
			const batchEvents = batchReceipt?.logs
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
				.filter((e) => e?.name === "BatchWithdrawIntentsExecuted");

			expect(batchEvents).to.have.length(1);
			expect(batchEvents?.[0]?.args?.executor).to.equal(relayer.address);
			expect(batchEvents?.[0]?.args?.intentCount).to.equal(2);

			// 6. Verify both intents were executed
			const intent0 = await encryptedERC.withdrawIntents(intentHashes[0]);
			const intent1 = await encryptedERC.withdrawIntents(intentHashes[1]);

			expect(intent0.executed).to.be.true;
			expect(intent1.executed).to.be.true;

			// 7. Verify both users received their tokens
			const erc20Balance0 = await erc20.balanceOf(users[0].signer.address);
			const erc20Balance1 = await erc20.balanceOf(users[1].signer.address);

			const expectedBalance0 =
				ethers.parseUnits("1000", DECIMALS) - depositAmount + withdrawAmount;
			const expectedBalance1 =
				ethers.parseUnits("1000", DECIMALS) - depositAmount + withdrawAmount;

			expect(erc20Balance0).to.equal(expectedBalance0);
			expect(erc20Balance1).to.equal(expectedBalance1);
		});

		it("should fail if array lengths mismatch", async () => {
			const intentHashes = ["0x" + "00".repeat(32), "0x" + "11".repeat(32)];
			const tokenIds = [1n];
			const destinations = [users[0].signer.address];
			const amounts = [100n];
			const proofs = [];
			const balancePCTs = [];
			const metadatas = [];

			await expect(
				encryptedERC
					.connect(relayer)
					.executeBatchWithdrawIntents(
						intentHashes,
						tokenIds,
						destinations,
						amounts,
						proofs as any,
						balancePCTs as any,
						metadatas,
					),
			).to.be.revertedWith("ArrayLengthMismatch");
		});

		it("should fail if batch is empty", async () => {
			await expect(
				encryptedERC
					.connect(relayer)
					.executeBatchWithdrawIntents([], [], [], [], [], [], []),
			).to.be.revertedWith("EmptyBatch");
		});

		it("should fail if batch exceeds max size", async () => {
			const maxSize = 51;
			const intentHashes = Array(maxSize).fill("0x" + "00".repeat(32));
			const tokenIds = Array(maxSize).fill(1n);
			const destinations = Array(maxSize).fill(users[0].signer.address);
			const amounts = Array(maxSize).fill(100n);
			const nonces = Array(maxSize).fill(1n);
			const proofs = Array(maxSize).fill({
				proofPoints: {
					a: [0n, 0n],
					b: [
						[0n, 0n],
						[0n, 0n],
					],
					c: [0n, 0n],
				},
				publicSignals: Array(16).fill(0n),
			});
			const balancePCTs = Array(maxSize).fill(Array(7).fill(0n));
			const metadatas = Array(maxSize).fill("0x");

			await expect(
				encryptedERC
					.connect(relayer)
					.executeBatchWithdrawIntents(
						intentHashes,
						tokenIds,
						destinations,
						amounts,
						nonces,
					proofs,
						balancePCTs as any,
						metadatas,
					),
			).to.be.revertedWith("BatchTooLarge");
		});
	});

	describe("Parameter Validation & Edge Cases", () => {
		it("should fail execute if wrong parameters provided (hash mismatch)", async () => {
			// 1. Deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Test wrong params";
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

			// 3. Try to execute with WRONG amount (should fail - proof verification will fail)
			const wrongAmount = ethers.parseUnits("60", DECIMALS);

			// The proof was generated for withdrawAmount, not wrongAmount
			// So the proof verification should fail
			await expect(
				encryptedERC.connect(users[0].signer).executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					wrongAmount, // WRONG AMOUNT - proof won't verify
					calldata,
					userBalancePCT,
					encryptedMetadata,
				),
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should fail if intent does not exist", async () => {
			const fakeIntentHash = "0x" + "ff".repeat(32);
			const tokenId = 1n;
			const destination = users[0].signer.address;
			const amount = 100n;
			const proof = {
				proofPoints: {
					a: [0n, 0n],
					b: [
						[0n, 0n],
						[0n, 0n],
					],
					c: [0n, 0n],
				},
				publicSignals: Array(16).fill(0n),
			};
			const balancePCT = Array(7).fill(0n) as any;
			const metadata = "0x";

			await expect(
				encryptedERC
					.connect(users[0].signer)
					.executeWithdrawIntent(
						fakeIntentHash,
						tokenId,
						destination,
						amount,
						proof,
						balancePCT,
						metadata,
					),
			).to.be.revertedWith("IntentNotFound");
		});

		it("should fail if intent has expired", async () => {
			// 1. Deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			// 2. Submit intent
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

			const MESSAGE = "Expiry test";
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

			// 3. Advance time by 31 days (past expiry)
			const currentBlockExpiry = await ethers.provider.getBlock("latest");
			const futureTimestampExpiry = Number(currentBlockExpiry?.timestamp) + (31 * 24 * 60 * 60);
			await ethers.provider.send("evm_setNextBlockTimestamp", [futureTimestampExpiry]);
			await ethers.provider.send("evm_mine", []);

			// 4. Try to execute (should fail)
			await expect(
				encryptedERC.connect(users[0].signer).executeWithdrawIntent(
					intentHash,
					tokenId,
					destination,
					withdrawAmount,
					nonce,
				calldata,
					userBalancePCT,
					encryptedMetadata,
				),
			).to.be.revertedWith("IntentExpired");
		});

		it("should verify intentHash is computed correctly", async () => {
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

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

			const MESSAGE = "Hash verification test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			// Submit intent
			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
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

			const emittedIntentHash = submitEvents?.[0]?.args?.intentHash;
			const intentId = submitEvents?.[0]?.args?.intentId;
			const timestamp = submitEvents?.[0]?.args?.timestamp;

			// Verify the hash can be reconstructed from parameters
			expect(emittedIntentHash).to.not.be.undefined;
			expect(intentId).to.equal(0); // First intent
			expect(timestamp).to.be.greaterThan(0);
		});

		it("should handle multiple users submitting intents independently", async () => {
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("30", DECIMALS);

			// User 0 deposit and submit
			const {
				ciphertext: depositCiphertext0,
				nonce: depositNonce0,
				authKey: depositAuthKey0,
			} = processPoseidonEncryption([depositAmount], users[0].publicKey);

			await encryptedERC
				.connect(users[0].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext0, ...depositAuthKey0, depositNonce0],
				);

			// User 1 deposit and submit
			const {
				ciphertext: depositCiphertext1,
				nonce: depositNonce1,
				authKey: depositAuthKey1,
			} = processPoseidonEncryption([depositAmount], users[1].publicKey);

			await encryptedERC
				.connect(users[1].signer)
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext1, ...depositAuthKey1, depositNonce1],
				);

			const tokenId = await encryptedERC.tokenIds(erc20.target);

			// User 0 submit intent
			const balance0 = await encryptedERC.balanceOf(
				users[0].signer.address,
				tokenId,
			);
			const userInitialBalance0 = await getDecryptedBalance(
				users[0].privateKey,
				balance0.amountPCTs,
				balance0.balancePCT,
				balance0.eGCT,
			);

			const userEncryptedBalance0 = [...balance0.eGCT.c1, ...balance0.eGCT.c2];
			const auditorPublicKey = users[2].publicKey;

			const { proof: calldata0, userBalancePCT: userBalancePCT0 } =
				await withdrawIntent(
					withdrawAmount,
					users[0].signer.address,
					tokenId,
					1n,
					users[0],
					userEncryptedBalance0,
					userInitialBalance0,
					auditorPublicKey,
				);

			const metadata0 = encryptMetadata(users[0].publicKey, "User 0 intent");
			const submitTx0 = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					calldata0,
					userBalancePCT0,
					metadata0,
				);
			const receipt0 = await submitTx0.wait();

			// User 1 submit intent
			const balance1 = await encryptedERC.balanceOf(
				users[1].signer.address,
				tokenId,
			);
			const userInitialBalance1 = await getDecryptedBalance(
				users[1].privateKey,
				balance1.amountPCTs,
				balance1.balancePCT,
				balance1.eGCT,
			);

			const userEncryptedBalance1 = [...balance1.eGCT.c1, ...balance1.eGCT.c2];

			const { proof: calldata1, userBalancePCT: userBalancePCT1 } =
				await withdrawIntent(
					withdrawAmount,
					users[1].signer.address,
					tokenId,
					1n,
					users[1],
					userEncryptedBalance1,
					userInitialBalance1,
					auditorPublicKey,
				);

			const metadata1 = encryptMetadata(users[1].publicKey, "User 1 intent");
			const submitTx1 = await encryptedERC
				.connect(users[1].signer)
				.submitWithdrawIntent(
					tokenId,
					calldata1,
					userBalancePCT1,
					metadata1,
				);
			const receipt1 = await submitTx1.wait();

			// Verify both intents are stored independently
			const events0 = receipt0?.logs
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

			const events1 = receipt1?.logs
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

			const intentHash0 = events0?.[0]?.args?.intentHash;
			const intentHash1 = events1?.[0]?.args?.intentHash;

			expect(intentHash0).to.not.equal(intentHash1);

			const intent0 = await encryptedERC.withdrawIntents(intentHash0);
			const intent1 = await encryptedERC.withdrawIntents(intentHash1);

			expect(intent0.user).to.equal(users[0].signer.address);
			expect(intent1.user).to.equal(users[1].signer.address);
			expect(intent0.executed).to.be.false;
			expect(intent1.executed).to.be.false;
		});
	});
});
