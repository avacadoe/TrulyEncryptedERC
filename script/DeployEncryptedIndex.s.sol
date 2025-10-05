// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script, console2} from "forge-std/Script.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {Point, CreateEncryptedERCParams} from "../contracts/types/Types.sol";

/**
 * @title DeployEncryptedIndex
 * @notice Deployment script for EncryptedERC with encrypted index functionality
 *
 * Usage:
 * forge script script/DeployEncryptedIndex.s.sol:DeployEncryptedIndex \
 *   --rpc-url fuji \
 *   --broadcast \
 *   --verify
 */
contract DeployEncryptedIndex is Script {
    // Fuji testnet addresses (you'll need to deploy these first or use existing ones)
    address constant REGISTRAR = address(0); // TODO: Set actual registrar address
    address constant MINT_VERIFIER = address(0); // TODO: Set actual verifier address
    address constant WITHDRAW_VERIFIER = address(0); // TODO: Set actual verifier address
    address constant TRANSFER_VERIFIER = address(0); // TODO: Set actual verifier address
    address constant BURN_VERIFIER = address(0); // TODO: Set actual verifier address

    // Auditor public key for address encryption (example values - generate real ones)
    uint256 constant AUDITOR_PUB_KEY_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 constant AUDITOR_PUB_KEY_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    function run() external {
        // Get deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console2.log("Deployer address:", deployer);
        console2.log("Deployer balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy EncryptedERC in converter mode
        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: REGISTRAR,
            isConverter: true, // Converter mode - wraps existing ERC20s
            name: "Encrypted ERC Token",
            symbol: "eERC",
            decimals: 18,
            mintVerifier: MINT_VERIFIER,
            withdrawVerifier: WITHDRAW_VERIFIER,
            transferVerifier: TRANSFER_VERIFIER,
            burnVerifier: BURN_VERIFIER
        });

        EncryptedERC encryptedERC = new EncryptedERC(params);

        console2.log("EncryptedERC deployed at:", address(encryptedERC));

        // Set auditor public key for address encryption
        Point memory auditorPubKey = Point({
            x: AUDITOR_PUB_KEY_X,
            y: AUDITOR_PUB_KEY_Y
        });

        encryptedERC.setAuditorPublicKeyForAddressEncryption(auditorPubKey);

        console2.log("Auditor public key for address encryption set");
        console2.log("Auditor PubKey X:", auditorPubKey.x);
        console2.log("Auditor PubKey Y:", auditorPubKey.y);

        vm.stopBroadcast();

        // Save deployment info
        console2.log("\n=== Deployment Summary ===");
        console2.log("Network: Fuji Testnet");
        console2.log("EncryptedERC:", address(encryptedERC));
        console2.log("Registrar:", REGISTRAR);
        console2.log("Auditor PubKey (X, Y):", auditorPubKey.x, auditorPubKey.y);
        console2.log("\nUpdate these addresses in dev-frontend/src/config/contracts.ts");
    }
}

/**
 * @title GenerateAuditorKeypair
 * @notice Script to generate auditor keypair for address encryption
 *
 * Usage:
 * forge script script/DeployEncryptedIndex.s.sol:GenerateAuditorKeypair
 */
contract GenerateAuditorKeypair is Script {
    function run() external view {
        // Generate a random private key (in production, use secure offline generation)
        uint256 privateKey = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao)));

        // Import BabyJubJub for key generation
        // For now, we'll use the generator point as an example

        console2.log("\n=== Auditor Keypair Generation ===");
        console2.log("WARNING: This is for testing only!");
        console2.log("In production, generate keys offline in a secure environment\n");

        console2.log("Private Key (KEEP SECRET):");
        console2.log(privateKey);

        console2.log("\nPublic Key will be: privateKey * Generator");
        console2.log("Use BabyJubJub.scalarMultiply(BabyJubJub.base8(), privateKey)");

        console2.log("\nGenerator Point (base8):");
        console2.log("X: 5299619240641551281634865583518297030282874472190772894086521144482721001553");
        console2.log("Y: 16950150798460657717958625567821834550301663161624707787222815936182638968203");
    }
}
