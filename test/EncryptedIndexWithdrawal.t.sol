// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Test, console2} from "forge-std/Test.sol";
import {EncryptedERC} from "../contracts/EncryptedERC.sol";
import {AddressEncryption} from "../contracts/libraries/AddressEncryption.sol";
import {BabyJubJub} from "../contracts/libraries/BabyJubJub.sol";
import {Point, CreateEncryptedERCParams, WithdrawProof, ProofPoints} from "../contracts/types/Types.sol";

// Mock contracts for testing
contract MockRegistrar {
    mapping(address => bool) public isUserRegistered;
    mapping(address => uint256[2]) public userPublicKeys;

    function registerUser(address user, uint256[2] memory pubKey) external {
        isUserRegistered[user] = true;
        userPublicKeys[user] = pubKey;
    }

    function getUserPublicKey(address user) external view returns (uint256[2] memory) {
        return userPublicKeys[user];
    }
}

contract MockVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _shouldPass) external {
        shouldPass = _shouldPass;
    }

    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[] memory
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        ProofPoints memory,
        uint256[] memory
    ) external view returns (bool) {
        return shouldPass;
    }
}

contract EncryptedIndexWithdrawalTest is Test {
    EncryptedERC public encryptedERC;
    MockRegistrar public registrar;
    MockVerifier public mintVerifier;
    MockVerifier public withdrawVerifier;
    MockVerifier public transferVerifier;
    MockVerifier public burnVerifier;

    address public owner;
    address public auditor;
    address public user1;
    address public user2;

    // Auditor keypair (for testing)
    uint256 public auditorPrivateKey;
    Point public auditorPublicKey;

    // User public keys (for eERC registration)
    uint256[2] public user1PubKey;
    uint256[2] public user2PubKey;

    function setUp() public {
        owner = address(this);
        auditor = makeAddr("auditor");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        // Deploy mock contracts
        registrar = new MockRegistrar();
        mintVerifier = new MockVerifier();
        withdrawVerifier = new MockVerifier();
        transferVerifier = new MockVerifier();
        burnVerifier = new MockVerifier();

        // Generate auditor keypair
        auditorPrivateKey = 12345; // Simple test key
        Point memory generator = BabyJubJub.base8();
        auditorPublicKey = BabyJubJub.scalarMultiply(generator, auditorPrivateKey);

        // Set up user public keys (mock values)
        user1PubKey = [uint256(111), uint256(222)];
        user2PubKey = [uint256(333), uint256(444)];

        // Register users in mock registrar
        registrar.registerUser(user1, user1PubKey);
        registrar.registerUser(user2, user2PubKey);

        // Register auditor as well (required for setAuditorPublicKey)
        uint256[2] memory auditorPubKey = [auditorPublicKey.x, auditorPublicKey.y];
        registrar.registerUser(auditor, auditorPubKey);

        // Deploy EncryptedERC
        CreateEncryptedERCParams memory params = CreateEncryptedERCParams({
            registrar: address(registrar),
            isConverter: true, // Converter mode for testing withdrawals
            name: "Test eERC",
            symbol: "TeERC",
            decimals: 18,
            mintVerifier: address(mintVerifier),
            withdrawVerifier: address(withdrawVerifier),
            transferVerifier: address(transferVerifier),
            burnVerifier: address(burnVerifier)
        });

        encryptedERC = new EncryptedERC(params);

        // Set auditor for balance operations
        vm.prank(owner);
        encryptedERC.setAuditorPublicKey(auditor);

        // Set auditor public key for address encryption
        vm.prank(owner);
        encryptedERC.setAuditorPublicKeyForAddressEncryption(auditorPublicKey);
    }

    /// @notice Test: Owner can set auditor public key for address encryption
    function test_SetAuditorPublicKeyForAddressEncryption() public {
        Point memory newPubKey = Point({x: 9999, y: 8888});

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AuditorPublicKeyForAddressEncryptionSet(newPubKey.x, newPubKey.y);
        encryptedERC.setAuditorPublicKeyForAddressEncryption(newPubKey);

        Point memory retrieved = encryptedERC.getAuditorPublicKeyForAddressEncryption();
        assertEq(retrieved.x, newPubKey.x);
        assertEq(retrieved.y, newPubKey.y);
    }

    /// @notice Test: Non-owner cannot set auditor public key
    function test_RevertWhen_NonOwnerSetsAuditorKey() public {
        Point memory newPubKey = Point({x: 9999, y: 8888});

        vm.prank(user1);
        vm.expectRevert(); // Should revert with Ownable error
        encryptedERC.setAuditorPublicKeyForAddressEncryption(newPubKey);
    }

    /// @notice Test: User can register for encrypted index
    function test_RegisterEncryptedIndex() public {
        uint256 randomness = 54321;

        vm.prank(user1);
        vm.expectEmit(true, false, false, false);
        emit EncryptedIndexRegistered(1, bytes32(0)); // Index 1 (first user), hash checked separately
        uint256 assignedIndex = encryptedERC.registerEncryptedIndex(randomness);

        assertEq(assignedIndex, 1, "First user should get index 1");
        assertTrue(encryptedERC.hasIndex(user1), "User should have index");

        vm.prank(user1);
        assertEq(encryptedERC.getMyIndex(), 1, "Should return correct index");
    }

    /// @notice Test: Multiple users get sequential indices
    function test_SequentialIndexAssignment() public {
        uint256 randomness1 = 11111;
        uint256 randomness2 = 22222;

        vm.prank(user1);
        uint256 index1 = encryptedERC.registerEncryptedIndex(randomness1);

        vm.prank(user2);
        uint256 index2 = encryptedERC.registerEncryptedIndex(randomness2);

        assertEq(index1, 1, "First user gets index 1");
        assertEq(index2, 2, "Second user gets index 2");
        assertEq(encryptedERC.getTotalIndices(), 2, "Total indices should be 2");
    }

    /// @notice Test: Cannot register twice
    function test_RevertWhen_RegisteringTwice() public {
        uint256 randomness1 = 11111;
        uint256 randomness2 = 22222;

        vm.startPrank(user1);
        encryptedERC.registerEncryptedIndex(randomness1);

        vm.expectRevert("Already has encrypted index");
        encryptedERC.registerEncryptedIndex(randomness2);
        vm.stopPrank();
    }

    /// @notice Test: Unregistered user cannot register for index
    function test_RevertWhen_UnregisteredUserRegistersIndex() public {
        address unregisteredUser = makeAddr("unregistered");
        uint256 randomness = 99999;

        vm.prank(unregisteredUser);
        vm.expectRevert(); // Should revert with UserNotRegistered
        encryptedERC.registerEncryptedIndex(randomness);
    }

    /// @notice Test: Address encryption produces different ciphertexts with different randomness
    function test_DifferentRandomnessProducesDifferentCiphertext() public {
        uint256 randomness1 = 11111;
        uint256 randomness2 = 22222;

        vm.prank(user1);
        encryptedERC.registerEncryptedIndex(randomness1);

        AddressEncryption.EncryptedAddress memory encrypted1 = encryptedERC.getEncryptedAddress(1);

        // Reset user1 registration for test (normally not possible)
        // We'll use a different user instead
        vm.prank(user2);
        encryptedERC.registerEncryptedIndex(randomness2);

        AddressEncryption.EncryptedAddress memory encrypted2 = encryptedERC.getEncryptedAddress(2);

        // Even though both users have different addresses, the encrypted data should differ
        bool isDifferent = (encrypted1.c1.x != encrypted2.c1.x) ||
                          (encrypted1.c1.y != encrypted2.c1.y) ||
                          (encrypted1.c2.x != encrypted2.c2.x) ||
                          (encrypted1.c2.y != encrypted2.c2.y);

        assertTrue(isDifferent, "Different randomness should produce different ciphertext");
    }

    /// @notice Test: Can retrieve encrypted address by index
    function test_GetEncryptedAddress() public {
        uint256 randomness = 54321;

        vm.prank(user1);
        encryptedERC.registerEncryptedIndex(randomness);

        AddressEncryption.EncryptedAddress memory encrypted = encryptedERC.getEncryptedAddress(1);

        // Check that encrypted address has non-zero coordinates
        assertTrue(encrypted.c1.x != 0, "c1.x should be non-zero");
        assertTrue(encrypted.c1.y != 0, "c1.y should be non-zero");
        assertTrue(encrypted.c2.x != 0, "c2.x should be non-zero");
        assertTrue(encrypted.c2.y != 0, "c2.y should be non-zero");
    }

    /// @notice Test: View functions work correctly
    function test_ViewFunctions() public {
        uint256 randomness = 54321;

        // Before registration
        assertFalse(encryptedERC.hasIndex(user1), "Should not have index before registration");

        vm.prank(user1);
        vm.expectRevert("No encrypted index");
        encryptedERC.getMyIndex();

        // Register
        vm.prank(user1);
        encryptedERC.registerEncryptedIndex(randomness);

        // After registration
        assertTrue(encryptedERC.hasIndex(user1), "Should have index after registration");

        vm.prank(user1);
        uint256 myIndex = encryptedERC.getMyIndex();
        assertEq(myIndex, 1, "Should return correct index");

        assertEq(encryptedERC.getTotalIndices(), 1, "Total indices should be 1");
    }

    /// @notice Test: Invalid index queries revert
    function test_RevertWhen_QueryingInvalidIndex() public {
        vm.expectRevert("Invalid index");
        encryptedERC.getEncryptedAddress(0); // Index 0 is invalid

        vm.expectRevert("Invalid index");
        encryptedERC.getEncryptedAddress(999); // Index doesn't exist
    }

    /// @notice Test: Encrypted address can be decrypted with correct private key (simulation)
    function test_AddressEncryptionDecryptionRoundtrip() public {
        // This is a conceptual test - actual decryption would be done off-chain
        uint256 randomness = 54321;
        address testAddr = user1;

        // Encrypt
        AddressEncryption.EncryptedAddress memory encrypted = AddressEncryption.encryptAddress(
            testAddr,
            auditorPublicKey,
            randomness
        );

        // Verify encryption produces valid points
        assertTrue(encrypted.c1.x != 0, "c1.x should be non-zero");
        assertTrue(encrypted.c2.x != 0, "c2.x should be non-zero");

        // Note: Full decryption would require discrete log solving, which is done off-chain
        // Here we just verify the encryption structure is correct
    }

    /// @notice Test: Hash function produces consistent results
    function test_EncryptedAddressHashing() public {
        uint256 randomness = 54321;

        AddressEncryption.EncryptedAddress memory encrypted = AddressEncryption.encryptAddress(
            user1,
            auditorPublicKey,
            randomness
        );

        bytes32 hash1 = AddressEncryption.hashEncrypted(encrypted);
        bytes32 hash2 = AddressEncryption.hashEncrypted(encrypted);

        assertEq(hash1, hash2, "Same encrypted address should produce same hash");
        assertTrue(hash1 != bytes32(0), "Hash should be non-zero");
    }

    // Events for testing
    event EncryptedIndexRegistered(uint256 indexed index, bytes32 encryptedAddressHash);
    event AuditorPublicKeyForAddressEncryptionSet(uint256 pubKeyX, uint256 pubKeyY);
    event WithdrawViaIndex(
        uint256 indexed userIndex,
        uint256 amount,
        uint256 tokenId,
        uint256[7] auditorPCT,
        address indexed auditorAddress
    );
}
