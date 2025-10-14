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
    // Fuji testnet addresses - Use OLD registrar where user is already registered
    address constant REGISTRAR = 0x37cA898f669bDE5257a191c716B50FA1480105F8;
    address constant MINT_VERIFIER = 0x5a73D582d0B267935Bc4561da2FA2a1b1cb1BC14;
    address constant WITHDRAW_VERIFIER = 0xa3Be1221F59d58b8F70FaFF4DF924c33fFFC3F4e;
    address constant TRANSFER_VERIFIER = 0x2Ecd1e34A826AfC48b29C42F9FBE6C45CBAeF98d;
    address constant BURN_VERIFIER = 0x2Ecd1e34A826AfC48b29C42F9FBE6C45CBAeF98d; // Using transfer verifier

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

        vm.stopBroadcast();
    }
}
