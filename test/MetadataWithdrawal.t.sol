// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {BabyJubJub, Point} from "../contracts/libraries/BabyJubJub.sol";
import {CreateEncryptedERCParams, WithdrawProof, ProofPoints} from "../contracts/types/Types.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// Mock contracts
import "../contracts/interfaces/IRegistrar.sol";
import "../contracts/interfaces/verifiers/IWithdrawVerifier.sol";
import "../contracts/interfaces/verifiers/IMintVerifier.sol";
import "../contracts/interfaces/verifiers/ITransferVerifier.sol";
import "../contracts/interfaces/verifiers/IBurnVerifier.sol";

contract MockRegistrar is IRegistrar {
    mapping(address => bool) public isUserRegistered;
    mapping(address => uint256[2]) public userPublicKeys;

    function registerUser(address user, uint256[2] memory publicKey) external {
        isUserRegistered[user] = true;
        userPublicKeys[user] = publicKey;
    }

    function getUserPublicKey(address user) external view returns (uint256[2] memory) {
        return userPublicKeys[user];
    }

    function register(bytes memory) external pure {}
    function burnUser() external pure returns (address) { return address(0x1111111111111111111111111111111111111111); }
}

contract MockWithdrawVerifier is IWithdrawVerifier {
    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[16] memory
    ) external pure returns (bool verified_) {
        return true; // Mock approval
    }
}

contract MockMintVerifier is IMintVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[24] memory) external pure returns (bool) { return true; }
}

contract MockTransferVerifier is ITransferVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[32] memory) external pure returns (bool) { return true; }
}

contract MockBurnVerifier is IBurnVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[19] memory) external pure returns (bool) { return true; }
}

contract MetadataWithdrawalTest is Test {
    EncryptedERC public encryptedERC;
    MockRegistrar public registrar;
    MockWithdrawVerifier public withdrawVerifier;

    // Test users
    address public mainWallet;
    uint256 public mainWalletPrivateKey;
    address public stealthWallet;
    uint256 public stealthWalletPrivateKey;
    address public recipient;
    address public auditor;

    // Crypto keys
    uint256 public auditorPrivateKey;
    Point public auditorPublicKey;
    uint256 public userPrivateKey;
    Point public userPublicKey;

    function setUp() public {
        // Generate wallets
        mainWalletPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        mainWallet = vm.addr(mainWalletPrivateKey);

        stealthWalletPrivateKey = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;
        stealthWallet = vm.addr(stealthWalletPrivateKey);

        recipient = makeAddr("recipient");
        auditor = makeAddr("auditor");

        // Generate crypto keys
        Point memory generator = BabyJubJub.base8();
        auditorPrivateKey = 12345;
        auditorPublicKey = BabyJubJub.scalarMultiply(generator, auditorPrivateKey);
        userPrivateKey = 98765;
        userPublicKey = BabyJubJub.scalarMultiply(generator, userPrivateKey);

        // Deploy contracts
        registrar = new MockRegistrar();
        withdrawVerifier = new MockWithdrawVerifier();

        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: address(registrar),
            isConverter: true,
            name: "Test",
            symbol: "TEST",
            decimals: 18,
            mintVerifier: address(new MockMintVerifier()),
            withdrawVerifier: address(withdrawVerifier),
            transferVerifier: address(new MockTransferVerifier()),
            burnVerifier: address(new MockBurnVerifier())
        });

        encryptedERC = new EncryptedERC(params);

        // Setup
        registrar.registerUser(mainWallet, [userPublicKey.x, userPublicKey.y]);
        registrar.registerUser(auditor, [auditorPublicKey.x, auditorPublicKey.y]);
        encryptedERC.setAuditorPublicKey(auditor);
    }

    function testMetadataSignatureGeneration() public view {
        // Mock encrypted proofs
        bytes memory userProof = hex"1234567890abcdef";
        bytes memory auditorProof = hex"fedcba0987654321";

        // Hash proofs (matching contract logic)
        bytes32 proofHash = keccak256(abi.encodePacked(userProof, auditorProof));

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        // Build EIP-712 struct hash
        bytes32 WITHDRAW_METADATA_TYPEHASH = keccak256(
            "WithdrawMetadataAuthorization(bytes32 proofHash,address recipient,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_METADATA_TYPEHASH,
                proofHash,
                recipient,
                nonce,
                deadline
            )
        );

        console.log("Metadata signature test passed");
        console.log("ProofHash:", uint256(proofHash));
        console.log("StructHash:", uint256(structHash));
    }

    function testWithdrawWithEncryptedProof() public {
        // Mock encrypted proofs
        bytes memory userProof = hex"1234567890abcdef1234567890abcdef";
        bytes memory auditorProof = hex"fedcba0987654321fedcba0987654321";

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        // Generate signature
        bytes32 proofHash = keccak256(abi.encodePacked(userProof, auditorProof));

        bytes32 WITHDRAW_METADATA_TYPEHASH = keccak256(
            "WithdrawMetadataAuthorization(bytes32 proofHash,address recipient,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_METADATA_TYPEHASH,
                proofHash,
                recipient,
                nonce,
                deadline
            )
        );

        // Compute domain separator
        bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 nameHash = keccak256(bytes("EncryptedERC"));
        bytes32 versionHash = keccak256(bytes("1"));
        bytes32 domainSeparator = keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(encryptedERC)));

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create mock proof
        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000), // amount
                userPublicKey.x, userPublicKey.y, // user public key
                uint256(100), uint256(200), // balance c1
                uint256(300), uint256(400), // balance c2
                auditorPublicKey.x, auditorPublicKey.y, // auditor public key
                uint256(500), uint256(600), // auditor pct
                uint256(700), uint256(800), uint256(900), // auditor pct continued
                uint256(1000), uint256(1100) // more auditor data
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7)];

        // Execute withdrawal from stealth wallet
        vm.prank(stealthWallet);
        encryptedERC.withdrawWithEncryptedProof(
            userProof,
            auditorProof,
            recipient,
            1, // tokenId
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Metadata withdrawal executed successfully");
    }

    function testCannotUseExpiredSignature() public {
        bytes memory userProof = hex"1234567890abcdef";
        bytes memory auditorProof = hex"fedcba0987654321";

        uint256 nonce = 1;
        uint256 deadline = block.timestamp - 1; // Expired

        bytes32 proofHash = keccak256(abi.encodePacked(userProof, auditorProof));
        bytes32 WITHDRAW_METADATA_TYPEHASH = keccak256(
            "WithdrawMetadataAuthorization(bytes32 proofHash,address recipient,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_METADATA_TYPEHASH,
                proofHash,
                recipient,
                nonce,
                deadline
            )
        );

        // Compute domain separator
        bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 nameHash = keccak256(bytes("EncryptedERC"));
        bytes32 versionHash = keccak256(bytes("1"));
        bytes32 domainSeparator = keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(encryptedERC)));

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000),
                userPublicKey.x, userPublicKey.y,
                uint256(100), uint256(200),
                uint256(300), uint256(400),
                auditorPublicKey.x, auditorPublicKey.y,
                uint256(500), uint256(600),
                uint256(700), uint256(800), uint256(900),
                uint256(1000), uint256(1100)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7)];

        vm.prank(stealthWallet);
        vm.expectRevert("Signature expired");
        encryptedERC.withdrawWithEncryptedProof(
            userProof,
            auditorProof,
            recipient,
            0,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Expired signature correctly rejected");
    }

    function testCannotReuseNonce() public {
        bytes memory userProof = hex"1234567890abcdef";
        bytes memory auditorProof = hex"fedcba0987654321";

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 proofHash = keccak256(abi.encodePacked(userProof, auditorProof));
        bytes32 WITHDRAW_METADATA_TYPEHASH = keccak256(
            "WithdrawMetadataAuthorization(bytes32 proofHash,address recipient,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_METADATA_TYPEHASH,
                proofHash,
                recipient,
                nonce,
                deadline
            )
        );

        // Compute domain separator
        bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 nameHash = keccak256(bytes("EncryptedERC"));
        bytes32 versionHash = keccak256(bytes("1"));
        bytes32 domainSeparator = keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(encryptedERC)));

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000),
                userPublicKey.x, userPublicKey.y,
                uint256(100), uint256(200),
                uint256(300), uint256(400),
                auditorPublicKey.x, auditorPublicKey.y,
                uint256(500), uint256(600),
                uint256(700), uint256(800), uint256(900),
                uint256(1000), uint256(1100)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7)];

        // First withdrawal succeeds
        vm.prank(stealthWallet);
        encryptedERC.withdrawWithEncryptedProof(
            userProof,
            auditorProof,
            recipient,
            0,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        // Second withdrawal with same nonce fails
        vm.prank(stealthWallet);
        vm.expectRevert("Nonce already used");
        encryptedERC.withdrawWithEncryptedProof(
            userProof,
            auditorProof,
            recipient,
            0,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Nonce reuse correctly prevented");
    }
}
