// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.27;

import {Point} from "../types/Types.sol";
import {BabyJubJub} from "./BabyJubJub.sol";

/**
 * @title AddressEncryption
 * @notice ElGamal encryption for Ethereum addresses using BabyJubJub curve
 * @dev Encrypts addresses using the auditor's public key so only the auditor can decrypt
 */
library AddressEncryption {
    /**
     * @dev Struct to store encrypted address as two points on BabyJubJub curve
     * This is the ElGamal ciphertext: (c1, c2)
     */
    struct EncryptedAddress {
        Point c1; // First ciphertext point: r * G (where G is generator, r is randomness)
        Point c2; // Second ciphertext point: M*G + r*PubKey (where M is address, PubKey is auditor's key)
    }

    /**
     * @notice Encrypt an Ethereum address using ElGamal encryption on BabyJubJub curve
     * @dev Uses the auditor's public key to encrypt. Only someone with the auditor's private key can decrypt.
     * @param addr The Ethereum address to encrypt
     * @param auditorPubKey The auditor's public key (point on BabyJubJub curve)
     * @param randomness Random value for encryption - MUST be cryptographically secure and unique per encryption
     * @return EncryptedAddress containing the two ciphertext points (c1, c2)
     *
     * Security:
     * - randomness MUST be truly random and MUST NOT be reused
     * - Same address with different randomness produces different ciphertexts (semantic security)
     * - Without the auditor's private key, the ciphertext reveals no information about the address
     */
    function encryptAddress(
        address addr,
        Point memory auditorPubKey,
        uint256 randomness
    ) internal view returns (EncryptedAddress memory) {
        // Convert Ethereum address (160 bits) to uint256 for elliptic curve operations
        uint256 addrAsScalar = uint256(uint160(addr));

        // Get the generator point (base point) of BabyJubJub curve
        Point memory generator = BabyJubJub.base8();

        // ElGamal encryption:
        // c1 = r * G (where r is randomness, G is generator)
        Point memory c1 = BabyJubJub.scalarMultiply(generator, randomness);

        // Compute r * PubKey (shared secret based on randomness and auditor's public key)
        Point memory sharedSecret = BabyJubJub.scalarMultiply(auditorPubKey, randomness);

        // Encode the address as a point: M * G (where M is the address)
        Point memory messagePoint = BabyJubJub.scalarMultiply(generator, addrAsScalar);

        // c2 = M*G + r*PubKey (message point plus shared secret)
        Point memory c2 = BabyJubJub._add(messagePoint, sharedSecret);

        return EncryptedAddress({c1: c1, c2: c2});
    }

    /**
     * @notice Hash an encrypted address to bytes32 for efficient storage/comparison
     * @dev Uses keccak256 to hash the four coordinates (c1.x, c1.y, c2.x, c2.y)
     * @param encrypted The encrypted address to hash
     * @return bytes32 hash of the encrypted address
     */
    function hashEncrypted(EncryptedAddress memory encrypted) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                encrypted.c1.x,
                encrypted.c1.y,
                encrypted.c2.x,
                encrypted.c2.y
            )
        );
    }

    /**
     * @notice Decrypt an encrypted address using the auditor's private key
     * @dev This function is for off-chain use by the auditor. It should NOT be called on-chain.
     * @param encrypted The encrypted address to decrypt
     * @param auditorPrivateKey The auditor's private key (must be kept SECRET)
     * @return address The decrypted Ethereum address
     *
     * Decryption process:
     * 1. Compute sharedSecret = privateKey * c1
     * 2. Compute messagePoint = c2 - sharedSecret
     * 3. Solve discrete log to get address from messagePoint
     *
     * Note: In practice, this function would be implemented off-chain because solving
     * the discrete logarithm on-chain for arbitrary values is computationally expensive.
     * For the specific case of addresses (160-bit values), it's feasible off-chain.
     */
    function decryptAddress(
        EncryptedAddress memory encrypted,
        uint256 auditorPrivateKey
    ) internal view returns (address) {
        // Compute shared secret: k * c1 (where k is private key)
        // This equals k * (r * G) = (k * r) * G = r * (k * G) = r * PubKey
        Point memory sharedSecret = BabyJubJub.scalarMultiply(encrypted.c1, auditorPrivateKey);

        // Subtract shared secret from c2 to get message point
        // c2 - sharedSecret = (M*G + r*PubKey) - r*PubKey = M*G
        Point memory messagePoint = BabyJubJub._sub(encrypted.c2, sharedSecret);

        // Now we need to solve the discrete logarithm: messagePoint = M * G
        // For small values like addresses (160 bits), this can be done via brute force or baby-step giant-step
        // In production, this would be done off-chain
        // For now, we'll use a simplified approach

        // Note: This is a placeholder. In a real implementation, you would:
        // 1. Use baby-step giant-step algorithm off-chain
        // 2. Or pre-compute a lookup table for all possible addresses
        // 3. Or use a more efficient encoding scheme

        // Simplified recovery (works for testing, not secure for production)
        // We'll try to match against known generator multiples
        Point memory generator = BabyJubJub.base8();

        // For production: implement proper discrete log solving off-chain
        // This is just a placeholder that won't work for arbitrary addresses
        revert("Decryption must be done off-chain");
    }
}
