import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";
import { expect } from "chai";
import { ethers, upgrades, zkit } from "hardhat";
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

describe("EncryptedERC - Two-Step Intent System (Private Intents)", () => {
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

		// Deploy the Converter EncryptedERC contract via UUPS proxy
		const encryptedERCFactory = new EncryptedERC__factory(
			{ "contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub },
			owner,
		);

		const proxy = await upgrades.deployProxy(
			encryptedERCFactory,
			[{
				registrar: registrar_.target,
				isConverter: true,
				name: "Encrypted Test Token",
				symbol: "eTEST",
				decimals: DECIMALS,
				mintVerifier,
				withdrawVerifier,
				withdrawIntentVerifier,
				transferVerifier,
				burnVerifier,
			}],
			{
				kind: "uups",
				initializer: "initialize",
				unsafeAllow: ["external-library-linking"],
			},
		);
		await proxy.waitForDeployment();
		const encryptedERC_ = proxy as unknown as EncryptedERC;

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

			const proof = await (registrationCircuit as unknown as RegistrationCircuit).generateProof(input);
			const calldata = await (registrationCircuit as unknown as RegistrationCircuit).generateCalldata(proof);

			await registrar.connect(user.signer).register({
				proofPoints: calldata.proofPoints,
				publicSignals: calldata.publicSignals,
			});
		}

		// Register relayer for auditor role
		const relayerUser = new User(relayer);
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

		await registrar.connect(relayer).register({
			proofPoints: relayerCalldata.proofPoints,
			publicSignals: relayerCalldata.publicSignals,
		});

		// Set auditor
		await encryptedERC.connect(owner).setAuditorPublicKey(relayer.address);

		// Set batch windows (1 day for testing)
		await encryptedERC.connect(owner).setBatchWindows([86400n]);
		// Pre-set denominations for tokenId=1 (first deposited token)
		await encryptedERC.connect(owner).setDenominations(1n, [ethers.parseUnits("50", DECIMALS)]);

		// Mint ERC20 tokens to users and approve EncryptedERC contract
		for (const user of users) {
			await erc20.connect(owner).mint(user.signer.address, ethers.parseUnits("10000", DECIMALS));
			await erc20.connect(user.signer).approve(encryptedERC.target, ethers.parseUnits("10000", DECIMALS));
		}
	};

	beforeEach(async () => {
		await deployFixture();
	});

	describe("submitWithdrawIntent (PRIVATE)", () => {
		it("should successfully submit a withdraw intent WITHOUT revealing amount/destination", async () => {
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			// 4. Create encrypted metadata
			const MESSAGE = "Two-step withdrawal intent for privacy";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			// 5. Submit intent (PRIVATE - amount and destination NOT in calldata!)
			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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
			const decryptedBalanceAfterSubmit = await getDecryptedBalance(
				users[0].privateKey,
				balanceAfterSubmit.amountPCTs,
				balanceAfterSubmit.balancePCT,
				balanceAfterSubmit.eGCT,
			);
			expect(decryptedBalanceAfterSubmit).to.equal(depositAmount);

			// 9. Verify balance has pending intent
			const hasPendingIntent = await encryptedERC.pendingIntents(
				users[0].signer.address,
				tokenId,
			);
			expect(hasPendingIntent).to.be.true;
		});

		it("should fail if user is not registered", async () => {
			const unregisteredSigner = signers[10];

			await expect(
				encryptedERC.connect(unregisteredSigner).submitWithdrawIntent(
					1n,
					0n,
					0n,
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
			const erc20BalanceBefore = await erc20.balanceOf(users[0].signer.address);

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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Immediate execution by user";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// 5. Verify withdrawal occurred (user received withdrawAmount back)
			const erc20BalanceAfter = await erc20.balanceOf(users[0].signer.address);
			expect(erc20BalanceAfter - erc20BalanceBefore).to.equal(withdrawAmount - depositAmount);

			// 6. Verify encrypted balance updated
			const finalBalance = await encryptedERC.balanceOf(
				users[0].signer.address,
				tokenId,
			);
			const decryptedFinalBalance = await getDecryptedBalance(
				users[0].privateKey,
				finalBalance.amountPCTs,
				finalBalance.balancePCT,
				finalBalance.eGCT,
			);
			expect(decryptedFinalBalance).to.equal(depositAmount - withdrawAmount);

			// 7. Verify intent marked as executed
			const intent = await encryptedERC.withdrawIntents(intentHash);
			expect(intent.executed).to.be.true;

			// 8. Verify balance lock released
			const hasPendingIntent = await encryptedERC.pendingIntents(
				users[0].signer.address,
				tokenId,
			);
			expect(hasPendingIntent).to.be.false;
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Testing relayer time restrictions";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should allow relayer to execute after 24 hours", async () => {
			// 1. Setup and deposit
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);
			const erc20BalanceBefore = await erc20.balanceOf(users[0].signer.address);

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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Relayer execution after 24 hours";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// 3. Advance time by 24 hours
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

			// 6. Verify withdrawal occurred (user received withdrawAmount back)
			const erc20BalanceAfter = await erc20.balanceOf(users[0].signer.address);
			expect(erc20BalanceAfter - erc20BalanceBefore).to.equal(withdrawAmount - depositAmount);
		});

		it("should fail if intent already executed", async () => {
			// 1. Setup, deposit, and submit intent
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Double execution test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});
	});

	describe("cancelWithdrawIntent", () => {
		it("should allow user to cancel their intent", async () => {
			// 1. Setup, deposit, and submit intent
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Cancellation test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// 2. Cancel the intent
			const cancelTx = await encryptedERC
				.connect(users[0].signer)
				.cancelWithdrawIntent(intentHash);
			const cancelReceipt = await cancelTx.wait();

			// 3. Verify cancellation event
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

			// 4. Verify intent marked as cancelled
			const intent = await encryptedERC.withdrawIntents(intentHash);
			expect(intent.cancelled).to.be.true;

			// 5. Verify balance lock released
			const hasPendingIntent = await encryptedERC.pendingIntents(
				users[0].signer.address,
				tokenId,
			);
			expect(hasPendingIntent).to.be.false;

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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should prevent non-owner from cancelling intent", async () => {
			// 1. Setup, deposit, and submit intent
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Non-owner cancellation test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// 2. Try to cancel with different user (should fail)
			await expect(
				encryptedERC.connect(users[1].signer).cancelWithdrawIntent(intentHash),
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});
	});

	describe("executeBatchWithdrawIntents", () => {
		it("should execute multiple intents in batch (PRIVACY VIA ANONYMITY SET!)", async () => {
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			const erc20BalanceBefore0 = await erc20.balanceOf(users[0].signer.address);
			const erc20BalanceBefore1 = await erc20.balanceOf(users[1].signer.address);

			// Deposit for both users
			for (let i = 0; i < 2; i++) {
				const {
					ciphertext: depositCiphertext,
					nonce: depositNonce,
					authKey: depositAuthKey,
				} = processPoseidonEncryption([depositAmount], users[i].publicKey);

				await encryptedERC
					.connect(users[i].signer)
					["deposit(uint256,address,uint256[7])"](
						depositAmount,
						erc20.target,
						[...depositCiphertext, ...depositAuthKey, depositNonce],
					);
			}

			const tokenId = await encryptedERC.tokenIds(erc20.target);
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];

			// 1. User 0 submit intent
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

			const { proof: calldata0, userBalancePCT: userBalancePCT0 } =
				await withdrawIntent(
					withdrawAmount,
					users[0].signer.address,
					tokenId,
					1n,
					users[0],
					userEncryptedBalance0,
					userInitialBalance0,
					auditorPubKey,
				);

			const encryptedMetadata0 = encryptMetadata(
				users[0].publicKey,
				"Batch intent 1",
			);

			const submitTx0 = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			const intentHash0 = submitEvents0?.[0]?.args?.intentHash;

			// 2. User 1 submit intent
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
					auditorPubKey,
				);

			const encryptedMetadata1 = encryptMetadata(
				users[1].publicKey,
				"Batch intent 2",
			);

			const submitTx1 = await encryptedERC
				.connect(users[1].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			const intentHash1 = submitEvents1?.[0]?.args?.intentHash;

			// 3. Prepare batch execution parameters
			const intentHashes = [intentHash0, intentHash1];
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

			// 5. Execute batch with relayer (CREATES ANONYMITY SET!)
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

			// 6. Verify batch execution event
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

			// 7. Verify both intents were executed
			const intent0 = await encryptedERC.withdrawIntents(intentHashes[0]);
			const intent1 = await encryptedERC.withdrawIntents(intentHashes[1]);

			expect(intent0.executed).to.be.true;
			expect(intent1.executed).to.be.true;

			// 8. Verify both users received their tokens (withdrew 50, deposited 100 → net -50)
			const erc20Balance0 = await erc20.balanceOf(users[0].signer.address);
			const erc20Balance1 = await erc20.balanceOf(users[1].signer.address);

			expect(erc20Balance0 - erc20BalanceBefore0).to.equal(withdrawAmount - depositAmount);
			expect(erc20Balance1 - erc20BalanceBefore1).to.equal(withdrawAmount - depositAmount);

			// 9. PRIVACY ACHIEVEMENT: Observer sees 2 withdrawals but cannot link
			//    which intentHash (from Day 1) corresponds to which withdrawal (Day 2)!
		});

		it("should fail if array lengths mismatch", async () => {
			const intentHashes = [
				"0x0000000000000000000000000000000000000000000000000000000000000000",
				"0x1111111111111111111111111111111111111111111111111111111111111111",
			];
			const tokenIds = [1n];
			const destinations = [users[0].signer.address];
			const amounts = [100n];
			const nonces = [];  // Intentionally wrong length
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
						nonces as any,
						proofs as any,
						balancePCTs as any,
						metadatas,
					),
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should fail if batch is empty", async () => {
			await expect(
				encryptedERC
					.connect(relayer)
					.executeBatchWithdrawIntents(
						[],
						[],
						[],
						[],
						[],
						[],
						[],
						[],
					),
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});
	});

	describe("Parameter Validation & Edge Cases", () => {
		it("should fail if intent does not exist", async () => {
			const fakeIntentHash = "0x" + "ff".repeat(32);

			await expect(
				encryptedERC.connect(users[0].signer).executeWithdrawIntent(
					fakeIntentHash,
					1n,
					users[0].signer.address,
					100n,
					1n,  // nonce
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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should fail if intent has expired", async () => {
			// 1. Setup and submit intent
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
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
				auditorPubKey,
			);

			const MESSAGE = "Expiry test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// 2. Advance time past expiry (30 days + 1 second — matches INTENT_EXPIRY constant)
			const currentBlock = await ethers.provider.getBlock("latest");
			const futureTimestamp = Number(currentBlock?.timestamp) + (30 * 24 * 60 * 60) + 1;
			await ethers.provider.send("evm_setNextBlockTimestamp", [futureTimestamp]);
			await ethers.provider.send("evm_mine", []);

			// 3. Try to execute (should fail)
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
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
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
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];
			const destination = users[0].signer.address;
			const nonce = 1n;

			const { proof: calldata, userBalancePCT, intentHash: expectedIntentHash } = await withdrawIntent(
				withdrawAmount,
				destination,
				tokenId,
				nonce,
				users[0],
				userEncryptedBalance,
				userInitialBalance,
				auditorPubKey,
			);

			const MESSAGE = "Hash verification test";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			// Submit intent
			const submitTx = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			const actualIntentHash = submitEvents?.[0]?.args?.intentHash;

			// Verify the hash from event matches what we computed
			expect(actualIntentHash).to.equal("0x" + expectedIntentHash.toString(16).padStart(64, "0"));

			// Verify proof.publicSignals[15] contains the intentHash
			const proofIntentHash = calldata.publicSignals[15];
			expect(actualIntentHash).to.equal("0x" + BigInt(proofIntentHash).toString(16).padStart(64, "0"));
		});

		it("should handle multiple users submitting intents independently", async () => {
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			// Deposit for both users
			for (let i = 0; i < 2; i++) {
				const {
					ciphertext: depositCiphertext,
					nonce: depositNonce,
					authKey: depositAuthKey,
				} = processPoseidonEncryption([depositAmount], users[i].publicKey);

				await encryptedERC
					.connect(users[i].signer)
					["deposit(uint256,address,uint256[7])"](
						depositAmount,
						erc20.target,
						[...depositCiphertext, ...depositAuthKey, depositNonce],
					);
			}

			const tokenId = await encryptedERC.tokenIds(erc20.target);
			const auditorPublicKey = await encryptedERC.auditorPublicKey();
			const auditorPubKey = [auditorPublicKey[0], auditorPublicKey[1]];

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

			const { proof: calldata0, userBalancePCT: userBalancePCT0 } =
				await withdrawIntent(
					withdrawAmount,
					users[0].signer.address,
					tokenId,
					1n,
					users[0],
					userEncryptedBalance0,
					userInitialBalance0,
					auditorPubKey,
				);

			const metadata0 = encryptMetadata(users[0].publicKey, "User 0 intent");
			const submitTx0 = await encryptedERC
				.connect(users[0].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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
					auditorPubKey,
				);

			const metadata1 = encryptMetadata(users[1].publicKey, "User 1 intent");
			const submitTx1 = await encryptedERC
				.connect(users[1].signer)
				.submitWithdrawIntent(
					tokenId,
					0n,
					0n,
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

			// Intent hashes should be different
			expect(intentHash0).to.not.equal(intentHash1);

			// Both intents should exist
			const intent0 = await encryptedERC.withdrawIntents(intentHash0);
			const intent1 = await encryptedERC.withdrawIntents(intentHash1);

			expect(intent0.user).to.equal(users[0].getAddress());
			expect(intent1.user).to.equal(users[1].getAddress());

			// Both should be pending
			expect(intent0.executed).to.be.false;
			expect(intent1.executed).to.be.false;
		});
	});
});
