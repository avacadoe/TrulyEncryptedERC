// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {BabyJubJub, Point} from "../contracts/libraries/BabyJubJub.sol";
import {CreateEncryptedERCParams, WithdrawProof, ProofPoints} from "../contracts/types/Types.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock contracts for testing
import "../contracts/interfaces/IRegistrar.sol";
import "../contracts/interfaces/verifiers/IMintVerifier.sol";
import "../contracts/interfaces/verifiers/IWithdrawVerifier.sol";
import "../contracts/interfaces/verifiers/ITransferVerifier.sol";
import "../contracts/interfaces/verifiers/IBurnVerifier.sol";

// Mock ERC20 token
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {
        _mint(msg.sender, 1000000 * 10**18);
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }
}

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
        return true; // Always approve for testing
    }
}

contract MockMintVerifier is IMintVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[24] memory) external pure returns (bool verified_) { return true; }
}

contract MockTransferVerifier is ITransferVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[32] memory) external pure returns (bool verified_) { return true; }
}

contract MockBurnVerifier is IBurnVerifier {
    function verifyProof(uint256[2] memory, uint256[2][2] memory, uint256[2] memory, uint256[19] memory) external pure returns (bool verified_) { return true; }
}

contract SignatureWithdrawalTest is Test {
    EncryptedERC public encryptedERC;
    MockRegistrar public registrar;
    MockWithdrawVerifier public withdrawVerifier;
    MockERC20 public mockToken;

    // Test users
    address public mainWallet;
    uint256 public mainWalletPrivateKey;

    address public stealthWallet;
    uint256 public stealthWalletPrivateKey;

    address public recipient;

    address public auditor;
    uint256 public auditorPrivateKey;
    Point public auditorPublicKey;

    // User keys
    uint256 public user1PrivateKey;
    Point public user1PubKey;

    uint256 public userIndex;

    function setUp() public {
        // Generate test wallets
        mainWalletPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        mainWallet = vm.addr(mainWalletPrivateKey);

        stealthWalletPrivateKey = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;
        stealthWallet = vm.addr(stealthWalletPrivateKey);

        recipient = makeAddr("recipient");

        // Generate auditor keypair
        auditorPrivateKey = 12345;
        Point memory generator = BabyJubJub.base8();
        auditorPublicKey = BabyJubJub.scalarMultiply(generator, auditorPrivateKey);
        auditor = makeAddr("auditor");

        // Generate user1 keypair
        user1PrivateKey = 98765;
        user1PubKey = BabyJubJub.scalarMultiply(generator, user1PrivateKey);

        // Deploy mock contracts
        registrar = new MockRegistrar();
        withdrawVerifier = new MockWithdrawVerifier();

        // Register users
        registrar.registerUser(mainWallet, [user1PubKey.x, user1PubKey.y]);
        registrar.registerUser(auditor, [auditorPublicKey.x, auditorPublicKey.y]);

        // Deploy EncryptedERC
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

        // Set auditor keys
        encryptedERC.setAuditorPublicKey(auditor);
        encryptedERC.setAuditorPublicKeyForAddressEncryption(auditorPublicKey);

        // Register encrypted index for main wallet
        vm.prank(mainWallet);
        userIndex = encryptedERC.registerEncryptedIndex(54321);

        // Deploy mock token and register it
        mockToken = new MockERC20();

        // Give main wallet some tokens for deposit
        mockToken.transfer(mainWallet, 50000 * 10**18);

        // Give EncryptedERC contract some tokens for withdrawals
        mockToken.transfer(address(encryptedERC), 50000 * 10**18);

        // Deposit to register the token (tokenId will be 1)
        uint256[7] memory amountPCT = [uint256(1), 2, 3, 4, 5, 6, 7];
        vm.prank(mainWallet);
        mockToken.approve(address(encryptedERC), 10000 * 10**18);
        vm.prank(mainWallet);
        encryptedERC.deposit(10000 * 10**18, address(mockToken), amountPCT);

        console.log("Main Wallet:", mainWallet);
        console.log("Stealth Wallet:", stealthWallet);
        console.log("Recipient:", recipient);
        console.log("User Index:", userIndex);
    }

    function testSignatureGeneration() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WithdrawAuthorization(uint256 index,address recipient,uint256 nonce,uint256 deadline)"),
                userIndex,
                recipient,
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EncryptedERC"),
                keccak256("1"),
                block.chainid,
                address(encryptedERC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        // Sign with main wallet
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature
        address recovered = ECDSA.recover(digest, signature);
        assertEq(recovered, mainWallet, "Signature recovery failed");

        console.log("Signature generated successfully");
        console.log("Recovered address:", recovered);
    }

    function testWithdrawViaIndexWithSignature() public {
        // Create mock proof
        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000), // amount
                user1PubKey.x,  // user public key X
                user1PubKey.y,  // user public key Y
                uint256(100),   // balance c1.x
                uint256(200),   // balance c1.y
                uint256(300),   // balance c2.x
                uint256(400),   // balance c2.y
                auditorPublicKey.x, // auditor public key X
                auditorPublicKey.y, // auditor public key Y
                uint256(10), uint256(20), uint256(30), uint256(40), // auditor PCT
                uint256(50), uint256(60), uint256(70)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), 2, 3, 4, 5, 6, 7];
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 tokenId = 1;

        // Generate signature from main wallet
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WithdrawAuthorization(uint256 index,address recipient,uint256 nonce,uint256 deadline)"),
                userIndex,
                recipient,
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EncryptedERC"),
                keccak256("1"),
                block.chainid,
                address(encryptedERC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        console.log("Signature created");
        console.log("Stealth wallet submitting transaction...");

        // Submit transaction from stealth wallet
        vm.prank(stealthWallet);
        encryptedERC.withdrawViaIndexWithSignature(
            userIndex,
            recipient,
            tokenId,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Transaction successful!");

        // Verify nonce was used
        assertTrue(encryptedERC.usedNonces(mainWallet, nonce), "Nonce should be marked as used");
    }

    function testCannotReuseNonce() public {
        // First withdrawal
        testWithdrawViaIndexWithSignature();

        // Try to reuse same nonce
        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000),
                user1PubKey.x, user1PubKey.y,
                uint256(100), uint256(200), uint256(300), uint256(400),
                auditorPublicKey.x, auditorPublicKey.y,
                uint256(10), uint256(20), uint256(30), uint256(40),
                uint256(50), uint256(60), uint256(70)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), 2, 3, 4, 5, 6, 7];
        uint256 nonce = 1; // Same nonce!
        uint256 deadline = block.timestamp + 3600;

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WithdrawAuthorization(uint256 index,address recipient,uint256 nonce,uint256 deadline)"),
                userIndex,
                recipient,
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EncryptedERC"),
                keccak256("1"),
                block.chainid,
                address(encryptedERC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert with "Nonce already used"
        vm.prank(stealthWallet);
        vm.expectRevert("Nonce already used");
        encryptedERC.withdrawViaIndexWithSignature(
            userIndex,
            recipient,
            1,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Nonce protection working correctly");
    }

    function testCannotUseExpiredSignature() public {
        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000),
                user1PubKey.x, user1PubKey.y,
                uint256(100), uint256(200), uint256(300), uint256(400),
                auditorPublicKey.x, auditorPublicKey.y,
                uint256(10), uint256(20), uint256(30), uint256(40),
                uint256(50), uint256(60), uint256(70)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), 2, 3, 4, 5, 6, 7];
        uint256 nonce = 2;
        uint256 deadline = block.timestamp - 1; // Expired!

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WithdrawAuthorization(uint256 index,address recipient,uint256 nonce,uint256 deadline)"),
                userIndex,
                recipient,
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EncryptedERC"),
                keccak256("1"),
                block.chainid,
                address(encryptedERC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mainWalletPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert with "Signature expired"
        vm.prank(stealthWallet);
        vm.expectRevert("Signature expired");
        encryptedERC.withdrawViaIndexWithSignature(
            userIndex,
            recipient,
            1,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Deadline protection working correctly");
    }

    function testCannotUseWrongSigner() public {
        // Create signature from DIFFERENT wallet
        uint256 wrongPrivateKey = 0xdeadbeef;

        WithdrawProof memory proof = WithdrawProof({
            proofPoints: ProofPoints({
                a: [uint256(1), uint256(2)],
                b: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
                c: [uint256(7), uint256(8)]
            }),
            publicSignals: [
                uint256(1000),
                user1PubKey.x, user1PubKey.y,
                uint256(100), uint256(200), uint256(300), uint256(400),
                auditorPublicKey.x, auditorPublicKey.y,
                uint256(10), uint256(20), uint256(30), uint256(40),
                uint256(50), uint256(60), uint256(70)
            ]
        });

        uint256[7] memory balancePCT = [uint256(1), 2, 3, 4, 5, 6, 7];
        uint256 nonce = 3;
        uint256 deadline = block.timestamp + 3600;

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("WithdrawAuthorization(uint256 index,address recipient,uint256 nonce,uint256 deadline)"),
                userIndex,
                recipient,
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EncryptedERC"),
                keccak256("1"),
                block.chainid,
                address(encryptedERC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest); // Wrong signer!
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert with "Signer does not own this index"
        vm.prank(stealthWallet);
        vm.expectRevert();
        encryptedERC.withdrawViaIndexWithSignature(
            userIndex,
            recipient,
            1,
            proof,
            balancePCT,
            signature,
            nonce,
            deadline
        );

        console.log("Wrong signer protection working correctly");
    }
}
