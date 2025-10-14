// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";

/**
 * @title SetAuditor
 * @notice Sets the auditor public key for the EncryptedERC contract
 *
 * The auditor must be a registered user in the eERC Registrar.
 * The contract will fetch their public key from the registrar.
 *
 * Usage:
 * forge script script/SetAuditor.s.sol:SetAuditor \
 *   --rpc-url https://api.avax-test.network/ext/bc/C/rpc \
 *   --broadcast
 *
 * Reads DEPLOYER_PRIVATE_KEY from .env file
 * Optional: Set AUDITOR_ADDRESS env var to use different auditor
 */
contract SetAuditor is Script {
    // Deployed contract address (Fuji testnet) - Fresh deployment Oct 10, 2025
    address constant ENCRYPTED_ERC = 0x65b92b0DC1BfD159759a3B2c97D3Eb1B8dd0B228;

    function run() external {
        // Get caller private key from env
        uint256 privateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address caller = vm.addr(privateKey);

        // Get auditor address (can be same as caller if they're registered)
        address auditorAddress = vm.envOr("AUDITOR_ADDRESS", caller);

        console.log("Caller:", caller);
        console.log("Setting auditor:", auditorAddress);

        EncryptedERC encryptedERC = EncryptedERC(ENCRYPTED_ERC);

        vm.startBroadcast(privateKey);

        // Set the auditor public key
        // This fetches the auditor's public key from the registrar
        encryptedERC.setAuditorPublicKey(auditorAddress);

        console.log("");
        console.log("Success! Auditor public key set for:", auditorAddress);
        console.log("");
        console.log("You can now deposit tokens!");

        vm.stopBroadcast();
    }
}
