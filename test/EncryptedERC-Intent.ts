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

describe("EncryptedERC - Intent-Based Withdrawals", () => {
	let registrar: Registrar;
	let users: User[];
	let signers: SignerWithAddress[];
	let owner: SignerWithAddress;
	let encryptedERC: EncryptedERC;
	let erc20: SimpleERC20;

	const deployFixture = async () => {
		signers = await ethers.getSigners();
		owner = signers[0];

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

		// Mint some ERC20 tokens to user 0
		const mintAmount = ethers.parseUnits("1000", DECIMALS);
		await erc20.connect(owner).mint(users[0].getAddress(), mintAmount);

		// Approve EncryptedERC to spend tokens
		await erc20
			.connect(users[0].getSigner())
			.approve(encryptedERC.target, mintAmount);
	};

	beforeEach(async () => {
		await deployFixture();
	});

	describe("withdrawWithIntent", () => {
		it("should successfully withdraw with encrypted intent metadata", async () => {
			// 1. Deposit tokens first
			const depositAmount = ethers.parseUnits("100", DECIMALS);
			const withdrawAmount = ethers.parseUnits("50", DECIMALS);

			// Create PCT for the deposit amount
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

			// Get token ID
			const tokenId = await encryptedERC.tokenIds(erc20.target);

			// 2. Get initial balance
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

			// 3. Prepare withdrawal with intent using new circuit
			const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];
			const auditorPublicKey = users[2].publicKey;

			// Generate withdraw intent proof with private amount
			const destination = users[0].signer.address; // Withdraw to self
			const nonce = 1n;

			const { proof: calldata, userBalancePCT, destinationAddress } = await withdrawIntent(
				withdrawAmount,
				destination,
				tokenId,
				nonce,
				users[0],
				userEncryptedBalance,
				userInitialBalance,
				auditorPublicKey,
			);

			// 4. Create encrypted intent metadata
			const MESSAGE = "WITHDRAW_INTENT transaction metadata testing.";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			// 5. Execute withdrawWithIntent
			const withdrawTx = await encryptedERC
				.connect(users[0].signer)
				.withdrawWithIntent(tokenId, destinationAddress, withdrawAmount, calldata, userBalancePCT, encryptedMetadata);

			const receipt = await withdrawTx.wait();

			// 6. Verify events
			// Should emit PrivateOperation event instead of Withdraw event
			const privateOpEvents = receipt?.logs
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
				.filter((e) => e?.name === "PrivateOperation");

			expect(privateOpEvents).to.have.length(1);
			expect(privateOpEvents?.[0]?.args?.user).to.equal(users[0].getAddress());
			expect(privateOpEvents?.[0]?.args?.operationType).to.equal(
				"WITHDRAW_INTENT",
			);

			// Should NOT emit Withdraw event
			const withdrawEvents = receipt?.logs
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
				.filter((e) => e?.name === "Withdraw");

			expect(withdrawEvents).to.have.length(0);

			// 7. Verify encrypted metadata was emitted
			const privateMessageEvents = receipt?.logs
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
				.filter((e) => e?.name === "PrivateMessage");

			expect(privateMessageEvents).to.have.length(1);

			// 8. Decrypt and verify metadata
			const encryptedMsg = privateMessageEvents?.[0]?.args?.metadata
				.encryptedMsg as string;
			const decryptedMetadata = decryptMetadata(
				users[0].privateKey,
				encryptedMsg,
			);

			expect(decryptedMetadata).to.equal(MESSAGE);

			// 9. Verify balance was actually withdrawn
			const erc20Balance = await erc20.balanceOf(users[0].signer.address);
			// User had 1000 tokens, deposited 100, so has 900
			// After withdrawing 50, should have 950
			const expectedERC20Balance = ethers.parseUnits("1000", DECIMALS) - depositAmount + withdrawAmount;
			expect(erc20Balance).to.equal(expectedERC20Balance);

			// 10. Verify encrypted balance was updated
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

		it("should fail if user is not registered", async () => {
			const unregisteredSigner = signers[10];

			await expect(
				encryptedERC.connect(unregisteredSigner).withdrawWithIntent(
					1n,
					unregisteredSigner.address,
					100n,
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

		it("should fail with invalid proof", async () => {
			// Deposit first
			const depositAmount = ethers.parseUnits("100", DECIMALS);

			// Create PCT for the deposit amount
			const {
				ciphertext: depositCiphertext,
				nonce: depositNonce,
				authKey: depositAuthKey,
			} = processPoseidonEncryption([depositAmount], users[0].getPublicKey());

			await encryptedERC
				.connect(users[0].getSigner())
				["deposit(uint256,address,uint256[7])"](
					depositAmount,
					erc20.target,
					[...depositCiphertext, ...depositAuthKey, depositNonce],
				);

			// Try to withdraw with invalid proof
			await expect(
				encryptedERC.connect(users[0].getSigner()).withdrawWithIntent(
					1n,
					users[0].getAddress(),
					100n,
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
					"0x1234", // encrypted metadata
				),
			).to.be.revertedWithCustomError(encryptedERC, "InvalidProof");
		});

		it("should successfully withdraw to an unregistered address", async () => {
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

			// 3. Use an unregistered address as destination
			const unregisteredDestination = signers[10].address;
			const userEncryptedBalance = [...balance.eGCT.c1, ...balance.eGCT.c2];
			const auditorPublicKey = users[2].publicKey;
			const nonce = 1n;

			const { proof: calldata, userBalancePCT, destinationAddress } = await withdrawIntent(
				withdrawAmount,
				unregisteredDestination,
				tokenId,
				nonce,
				users[0],
				userEncryptedBalance,
				userInitialBalance,
				auditorPublicKey,
			);

			// 4. Execute withdrawWithIntent to unregistered address
			const MESSAGE = "Withdrawing to fresh address for privacy";
			const encryptedMetadata = encryptMetadata(users[0].publicKey, MESSAGE);

			const withdrawTx = await encryptedERC
				.connect(users[0].signer)
				.withdrawWithIntent(tokenId, destinationAddress, withdrawAmount, calldata, userBalancePCT, encryptedMetadata);

			await withdrawTx.wait();

			// 5. Verify ERC20 tokens went to the unregistered address (not msg.sender)
			const destinationERC20Balance = await erc20.balanceOf(unregisteredDestination);
			expect(destinationERC20Balance).to.equal(withdrawAmount);

			// 6. Verify msg.sender did NOT receive the tokens
			const senderERC20Balance = await erc20.balanceOf(users[0].signer.address);
			// User had 1000 tokens, deposited 100, so has 900
			const expectedSenderBalance = ethers.parseUnits("1000", DECIMALS) - depositAmount;
			expect(senderERC20Balance).to.equal(expectedSenderBalance);

			// 7. Verify encrypted balance was updated for msg.sender (not destination)
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
	});
});
