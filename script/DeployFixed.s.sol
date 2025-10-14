// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {CreateEncryptedERCParams} from "../contracts/types/Types.sol";

/**
 * @title DeployFixed
 * @notice Deploy FIXED EncryptedERC with correct recipient handling and PrivateMessage events
 */
contract DeployFixed is Script {
    // Existing Fuji testnet addresses (reusing verifiers)
    address constant REGISTRAR = 0x37cA898f669bDE5257a191c716B50FA1480105F8;
    address constant MINT_VERIFIER = 0x816C924218e21d0357Aea93A8d6BbBeCc5716Da3;
    address constant WITHDRAW_VERIFIER = 0x4DcB78AA27E13bCa903a0efFdc651bDc2E4b2995;
    address constant TRANSFER_VERIFIER = 0xECE998A00FEe6fDEA8190e30892952AF82a843E1;
    address constant BURN_VERIFIER = 0x34c975d8d8B3D6A59F445f003FE14f1E3e51fC08;

    function run() external {
        // Get deployer private key from env
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("========================================");
        console.log("DEPLOYING FIXED EERC CONTRACT");
        console.log("========================================");
        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance);
        console.log("");
        console.log("Fixes:");
        console.log("1. Tokens sent to recipient (not msg.sender)");
        console.log("2. PrivateMessage events emitted for history");
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy EncryptedERC in converter mode
        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: REGISTRAR,
            isConverter: true,
            name: "",
            symbol: "",
            decimals: 18,
            mintVerifier: MINT_VERIFIER,
            withdrawVerifier: WITHDRAW_VERIFIER,
            transferVerifier: TRANSFER_VERIFIER,
            burnVerifier: BURN_VERIFIER
        });

        EncryptedERC encryptedERC = new EncryptedERC(params);

        console.log("========================================");
        console.log("DEPLOYMENT SUCCESSFUL");
        console.log("========================================");
        console.log("NEW EncryptedERC:", address(encryptedERC));
        console.log("");
        console.log("OLD BUGGY CONTRACT: 0x65b92b0DC1BfD159759a3B2c97D3Eb1B8dd0B228");
        console.log("NEW FIXED CONTRACT:", address(encryptedERC));
        console.log("");
        console.log("Next steps:");
        console.log("1. Set auditor: cast send", address(encryptedERC), "'setAuditorPublicKey(address)' 0xF92Af9b54dBDe2C5182fee869eff084023E5a1C4");
        console.log("2. Update frontend: src/config/contracts.ts");
        console.log("3. Test withdrawal to verify fix");
        console.log("========================================");

        vm.stopBroadcast();
    }
}
