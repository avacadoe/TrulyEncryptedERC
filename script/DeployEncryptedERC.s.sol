// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {Registrar} from "../contracts/Registrar.sol";
import {CreateEncryptedERCParams} from "../contracts/types/Types.sol";

/**
 * @title DeployEncryptedERC
 * @notice Deployment script for EncryptedERC with signature-based stealth withdrawals
 *
 * Usage:
 * forge script script/DeployEncryptedERC.s.sol:DeployEncryptedERC \
 *   --rpc-url https://api.avax-test.network/ext/bc/C/rpc \
 *   --broadcast \
 *   --verify
 */
contract DeployEncryptedERC is Script {
    // Fuji testnet addresses (update these)
    address constant REGISTRAR = address(0); // TODO: Deploy Registrar first
    address constant MINT_VERIFIER = address(0); // TODO: Update
    address constant WITHDRAW_VERIFIER = address(0); // TODO: Update
    address constant TRANSFER_VERIFIER = address(0); // TODO: Update
    address constant BURN_VERIFIER = address(0); // TODO: Update

    function run() external {
        // Get deployer private key from env
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying from:", deployer);
        console.log("Balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy EncryptedERC in converter mode
        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: REGISTRAR,
            isConverter: true,
            name: "", // Not used in converter mode
            symbol: "", // Not used in converter mode
            decimals: 18,
            mintVerifier: MINT_VERIFIER,
            withdrawVerifier: WITHDRAW_VERIFIER,
            transferVerifier: TRANSFER_VERIFIER,
            burnVerifier: BURN_VERIFIER
        });

        EncryptedERC encryptedERC = new EncryptedERC(params);

        console.log("EncryptedERC deployed at:", address(encryptedERC));
        console.log("");
        console.log("IMPORTANT: Save this address to frontend config!");
        console.log("");
        console.log("Next steps:");
        console.log("1. Set auditor public key:");
        console.log("   cast send", address(encryptedERC));
        console.log("   'setAuditorPublicKey(address)' <AUDITOR_ADDRESS>");
        console.log("");
        console.log("2. Set auditor public key for address encryption:");
        console.log("   cast send", address(encryptedERC));
        console.log("   'setAuditorPublicKeyForAddressEncryption((uint256,uint256))'");
        console.log("   '(<PUBKEY_X>,<PUBKEY_Y>)'");

        vm.stopBroadcast();
    }
}
