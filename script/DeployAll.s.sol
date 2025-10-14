// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {Registrar} from "../contracts/Registrar.sol";
import {CreateEncryptedERCParams} from "../contracts/types/Types.sol";

// Import verifiers
import {MintVerifier} from "../contracts/prod/MintVerifier.sol";
import {WithdrawVerifier} from "../contracts/prod/WithdrawVerifier.sol";
import {TransferVerifier} from "../contracts/prod/TransferVerifier.sol";
import {BurnVerifier} from "../contracts/prod/BurnVerifier.sol";
import {RegistrationVerifier} from "../contracts/prod/RegistrationVerifier.sol";

/**
 * @title DeployAll
 * @notice Complete deployment script for EncryptedERC system
 *
 * Usage:
 * export PRIVATE_KEY="your-private-key"
 * export FUJI_RPC_URL="https://api.avax-test.network/ext/bc/C/rpc"
 *
 * forge script script/DeployAll.s.sol:DeployAll \
 *   --rpc-url $FUJI_RPC_URL \
 *   --broadcast \
 *   --legacy
 */
contract DeployAll is Script {
    function run() external {
        // Get deployer private key from env
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("=================================================");
        console.log("Deploying EncryptedERC System to Fuji Testnet");
        console.log("=================================================");
        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance / 1e18, "AVAX");
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy verifiers
        console.log("Step 1: Deploying Verifiers...");
        MintVerifier mintVerifier = new MintVerifier();
        console.log("  MintVerifier:", address(mintVerifier));

        WithdrawVerifier withdrawVerifier = new WithdrawVerifier();
        console.log("  WithdrawVerifier:", address(withdrawVerifier));

        TransferVerifier transferVerifier = new TransferVerifier();
        console.log("  TransferVerifier:", address(transferVerifier));

        BurnVerifier burnVerifier = new BurnVerifier();
        console.log("  BurnVerifier:", address(burnVerifier));

        RegistrationVerifier registrationVerifier = new RegistrationVerifier();
        console.log("  RegistrationVerifier:", address(registrationVerifier));
        console.log("");

        // Step 2: Deploy Registrar
        console.log("Step 2: Deploying Registrar...");
        Registrar registrar = new Registrar(address(registrationVerifier));
        console.log("  Registrar:", address(registrar));
        console.log("");

        // Step 3: Deploy EncryptedERC
        console.log("Step 3: Deploying EncryptedERC...");
        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: address(registrar),
            isConverter: true,
            name: "",
            symbol: "",
            decimals: 18,
            mintVerifier: address(mintVerifier),
            withdrawVerifier: address(withdrawVerifier),
            transferVerifier: address(transferVerifier),
            burnVerifier: address(burnVerifier)
        });

        EncryptedERC encryptedERC = new EncryptedERC(params);
        console.log("  EncryptedERC:", address(encryptedERC));
        console.log("");

        vm.stopBroadcast();

        // Print summary
        console.log("=================================================");
        console.log("Deployment Complete!");
        console.log("=================================================");
        console.log("");
        console.log("Contract Addresses:");
        console.log("-------------------");
        console.log("MintVerifier:        ", address(mintVerifier));
        console.log("WithdrawVerifier:    ", address(withdrawVerifier));
        console.log("TransferVerifier:    ", address(transferVerifier));
        console.log("BurnVerifier:        ", address(burnVerifier));
        console.log("RegistrationVerifier:", address(registrationVerifier));
        console.log("Registrar:           ", address(registrar));
        console.log("EncryptedERC:        ", address(encryptedERC));
        console.log("");
        console.log("Next Steps:");
        console.log("-----------");
        console.log("1. Set auditor address:");
        console.log("   cast send", address(encryptedERC), "\\");
        console.log("   'setAuditorPublicKey(address)' <AUDITOR_ADDRESS> \\");
        console.log("   --rpc-url $FUJI_RPC_URL --private-key $PRIVATE_KEY");
        console.log("");
        console.log("2. Update frontend config with EncryptedERC address:");
        console.log("   ", address(encryptedERC));
        console.log("");
        console.log("3. Test metadata withdrawal with SDK");
        console.log("");
    }
}
