# Encrypted Index Withdrawal System

## Overview

This document describes the encrypted index-based withdrawal system implemented in the EncryptedERC contract. This system provides enhanced privacy by hiding user addresses from transaction events and logs while maintaining the ability for authorized auditors to decrypt addresses when necessary.

## Core Concept

Instead of exposing user addresses in withdrawal events, users are assigned encrypted indices. When withdrawing, only the index number appears in transaction events - the actual address is encrypted and can only be decrypted by the auditor using their private key.

## Architecture

### Components

1. **AddressEncryption Library** (`contracts/libraries/AddressEncryption.sol`)
   - Implements ElGamal encryption on BabyJubJub elliptic curve
   - Encrypts Ethereum addresses using auditor's public key
   - Provides hash function for encrypted addresses

2. **EncryptedERC Contract** (`contracts/EncryptedERC.sol`)
   - Extended with encrypted index state variables
   - New functions: `registerEncryptedIndex()`, `withdrawViaIndex()`
   - View functions for querying indices and encrypted addresses

### Privacy Model

**What is Hidden:**
- User addresses in withdrawal events (only index shown)
- Address-to-index mapping (stored encrypted on-chain)
- Historical lookups (events don't reveal addresses)

**What is NOT Hidden:**
- Transaction `msg.sender` (blockchain limitation - appears in transaction metadata)
- Index numbers (publicly visible, but unlinkable to addresses without auditor key)
- Withdrawal amounts and tokenIds

**Privacy Level:** Events and logs provide privacy. Transaction metadata still shows `msg.sender`. For full privacy, a relayer system would be needed (future enhancement).

## How It Works

### 1. Auditor Setup (Owner Only)

The contract owner sets the auditor's public key for address encryption:

```solidity
// Auditor generates keypair off-chain
// Private key: kept secret by auditor
// Public key: set on-chain

function setAuditorPublicKeyForAddressEncryption(Point memory pubKey) external onlyOwner
```

### 2. User Registration (One-Time)

Users register for an encrypted index before they can use privacy-preserving withdrawals:

```solidity
// User generates randomness client-side (must be cryptographically secure)
uint256 randomness = generateSecureRandom();

// Register and get assigned index
uint256 myIndex = registerEncryptedIndex(randomness);
```

**What Happens:**
1. User's address is encrypted using ElGamal: `encryptedAddr = encrypt(userAddress, auditorPubKey, randomness)`
2. User is assigned next available index (e.g., index = 5)
3. Encrypted address stored: `indexToEncryptedAddress[5] = encryptedAddr`
4. Reverse mapping stored (private): `addressToIndex[userAddress] = 5`
5. Event emitted: `EncryptedIndexRegistered(index=5, encryptedHash=0xabc...)`

**Important:**
- Users can only register ONCE
- Randomness is used once then discarded
- Different randomness produces different ciphertext (semantic security)

### 3. Privacy-Preserving Withdrawal

Users withdraw using their index instead of exposing their address:

```solidity
// Normal withdrawal (address exposed in events)
withdraw(tokenId, proof, balancePCT);
// Event: Withdraw(address=0xUser, amount, tokenId, ...)

// Privacy-preserving withdrawal (only index exposed)
withdrawViaIndex(myIndex, tokenId, proof, balancePCT);
// Event: WithdrawViaIndex(index=5, amount, tokenId, ...)
```

**Verification:**
- Contract checks: `addressToIndex[msg.sender] == userIndex`
- Prevents users from using someone else's index
- Same ZK proof verification as normal withdrawal

### 4. Auditor Decryption

Only the auditor with the private key can decrypt addresses:

```javascript
// Off-chain decryption (auditor only)
const encryptedAddr = await contract.getEncryptedAddress(index);
const userAddress = decryptWithPrivateKey(encryptedAddr, auditorPrivateKey);
```

**Decryption Process:**
1. Retrieve encrypted address: `(c1, c2)` from `getEncryptedAddress(index)`
2. Compute shared secret: `sharedSecret = auditorPrivateKey * c1`
3. Decrypt: `userAddress = c2 - sharedSecret` (on elliptic curve)
4. Convert point back to Ethereum address

## Smart Contract Functions

### Registration & Setup

#### `setAuditorPublicKeyForAddressEncryption(Point memory pubKey)`
- **Access:** Owner only
- **Purpose:** Set auditor's public key for address encryption
- **Parameters:**
  - `pubKey`: Point on BabyJubJub curve (auditor's public key)

#### `registerEncryptedIndex(uint256 randomness)`
- **Access:** Registered users only
- **Purpose:** Register for encrypted index (one-time)
- **Parameters:**
  - `randomness`: Cryptographically secure random number (generated client-side)
- **Returns:** `userIndex` - the assigned index
- **Requirements:**
  - User must be registered in eERC system
  - User must not already have index
  - Auditor public key must be set

### Withdrawal

#### `withdrawViaIndex(uint256 userIndex, uint256 tokenId, WithdrawProof memory proof, uint256[7] memory balancePCT)`
- **Access:** Registered users with encrypted index
- **Purpose:** Withdraw using encrypted index (privacy-preserving)
- **Parameters:**
  - `userIndex`: User's assigned index
  - `tokenId`: Token to withdraw
  - `proof`: ZK proof of sufficient balance
  - `balancePCT`: Balance PCT for verification
- **Requirements:**
  - User must have encrypted index
  - Caller must own the specified index
  - Must pass ZK proof verification

### View Functions

#### `getMyIndex()`
- **Returns:** Caller's assigned index
- **Reverts if:** Caller has no index

#### `hasIndex(address user)`
- **Returns:** `true` if user has encrypted index, `false` otherwise

#### `getEncryptedAddress(uint256 index)`
- **Returns:** Encrypted address struct (two points on curve)
- **Use:** Auditor retrieves this to decrypt

#### `getAuditorPublicKeyForAddressEncryption()`
- **Returns:** Auditor's public key point

#### `getTotalIndices()`
- **Returns:** Total number of registered indices

## Events

### `EncryptedIndexRegistered(uint256 indexed index, bytes32 encryptedAddressHash)`
- Emitted when user registers for encrypted index
- Only hash of encrypted address is included (not actual address)

### `WithdrawViaIndex(uint256 indexed userIndex, uint256 amount, uint256 tokenId, uint256[7] auditorPCT, address indexed auditorAddress)`
- Emitted on index-based withdrawal
- Shows index instead of user address (privacy-preserving)

### `AuditorPublicKeyForAddressEncryptionSet(uint256 pubKeyX, uint256 pubKeyY)`
- Emitted when auditor public key is set

## Security Considerations

### Cryptographic Security
- Uses BabyJubJub elliptic curve (same as used in Circom/ZK circuits)
- ElGamal encryption provides semantic security
- Randomness MUST be cryptographically secure and unique per registration
- Security relies on elliptic curve discrete logarithm problem (ECDLP) hardness

### Key Management
- **Auditor Private Key:** Must be kept absolutely secret
  - Compromise = all addresses can be decrypted
  - Should be stored in HSM or split via threshold cryptography
- **User Randomness:** Generated client-side, used once, then discarded
  - Never stored on-chain or in contract
  - Different randomness = different ciphertext (unlinkability)

### Privacy Limitations
- **Transaction Metadata:** `msg.sender` is still visible in transaction data
  - Observers can link: "0xUserAddr used index 5"
  - BUT events show only index, providing some privacy
  - For full privacy, use relayer (future enhancement)
- **Index Reuse:** Same index used for all withdrawals
  - Observers can track: "Index 5 withdrew 3 times"
  - BUT cannot determine which address owns index 5

### Attack Vectors
- **Front-Running Registration:** Attacker sees registration tx in mempool
  - Mitigation: ZK proof of ownership (to be implemented)
- **Index Enumeration:** Auditor can decrypt all indices
  - Accepted tradeoff for compliance/auditability
- **Quantum Computing:** Future quantum computers could break ECDLP
  - Long-term consideration for sensitive applications

## Implementation Details

### ElGamal Encryption on BabyJubJub

**Encryption:**
```
Given:
- M = user address (as uint256)
- G = generator point on BabyJubJub
- P = auditor public key (point on curve)
- r = randomness (scalar)

Compute:
- c1 = r * G
- c2 = (M * G) + (r * P)

Output: (c1, c2) = encrypted address
```

**Decryption (auditor only):**
```
Given:
- (c1, c2) = encrypted address
- k = auditor private key (where P = k * G)

Compute:
- sharedSecret = k * c1 = k * (r * G) = r * (k * G) = r * P
- messagePoint = c2 - sharedSecret = (M * G)
- M = discreteLog(messagePoint, G)  // Solve for M

Output: M = user address
```

### Storage Layout

```solidity
// Encrypted address struct
struct EncryptedAddress {
    Point c1;  // First ciphertext point (r * G)
    Point c2;  // Second ciphertext point (M*G + r*P)
}

// State variables
mapping(uint256 => EncryptedAddress) private indexToEncryptedAddress;
mapping(address => uint256) private addressToIndex;
mapping(address => bool) private hasEncryptedIndex;
uint256 private nextIndex = 1;
Point private auditorPublicKeyForAddressEncryption;
```

## Usage Examples

### Frontend Integration

```javascript
// 1. Check if user has index
const hasIndex = await contract.hasIndex(userAddress);

if (!hasIndex) {
    // 2. Generate secure randomness
    const randomness = ethers.BigNumber.from(ethers.utils.randomBytes(32));

    // 3. Register for encrypted index
    const tx = await contract.registerEncryptedIndex(randomness);
    await tx.wait();

    // 4. Get assigned index
    const myIndex = await contract.getMyIndex();
    console.log(`Assigned index: ${myIndex}`);
}

// 5. Withdraw using index (privacy-preserving)
const myIndex = await contract.getMyIndex();
const tx = await contract.withdrawViaIndex(
    myIndex,
    tokenId,
    proof,
    balancePCT
);
await tx.wait();

// Event emitted: WithdrawViaIndex(index=myIndex, ...)
// User address NOT in event, only index!
```

### Auditor Decryption (Off-Chain)

```javascript
// Auditor decrypts an address from index
async function decryptAddress(index, auditorPrivateKey) {
    // 1. Get encrypted address from contract
    const encrypted = await contract.getEncryptedAddress(index);

    // 2. Perform ElGamal decryption
    const c1 = { x: encrypted.c1.x, y: encrypted.c1.y };
    const c2 = { x: encrypted.c2.x, y: encrypted.c2.y };

    // 3. Compute shared secret: k * c1
    const sharedSecret = scalarMultiply(c1, auditorPrivateKey);

    // 4. Decrypt: c2 - sharedSecret
    const messagePoint = pointSubtract(c2, sharedSecret);

    // 5. Solve discrete log to get address
    const address = discreteLogToAddress(messagePoint);

    return address;
}
```

## Deployment Steps

1. **Deploy EncryptedERC contract** (with all verifiers, etc.)

2. **Generate auditor keypair** (off-chain, secure environment)
   ```javascript
   const { privateKey, publicKey } = generateBabyJubJubKeypair();
   // Store privateKey securely (HSM)
   ```

3. **Set auditor public key** (owner only)
   ```javascript
   await contract.setAuditorPublicKeyForAddressEncryption(publicKey);
   ```

4. **Users register** for encrypted indices
   ```javascript
   const randomness = generateSecureRandom();
   await contract.registerEncryptedIndex(randomness);
   ```

5. **Users withdraw** using indices
   ```javascript
   const myIndex = await contract.getMyIndex();
   await contract.withdrawViaIndex(myIndex, tokenId, proof, balancePCT);
   ```

## Future Enhancements

### Relayer Support (Full Privacy)
Add signature-based withdrawal to hide `msg.sender`:

```solidity
function withdrawViaIndexWithSignature(
    uint256 userIndex,
    uint256 tokenId,
    WithdrawProof memory proof,
    uint256[7] memory balancePCT,
    bytes memory userSignature
) external {
    // Recover user address from signature
    address user = recoverSigner(userIndex, tokenId, userSignature);

    // Verify user owns this index
    require(addressToIndex[user] == userIndex);

    // msg.sender is now RELAYER, not user!
    // Execute withdrawal...
}
```

### Threshold Auditor
- Split auditor private key among N parties
- Require M-of-N to cooperate for decryption
- Reduces single point of failure

### Deposit Via Index
- Extend system to hide addresses in deposits too
- `depositViaIndex(userIndex, amount, proof)`
- Complete privacy flow: deposit → withdraw

## Testing

See `test/EncryptedIndexWithdrawal.t.sol` for comprehensive tests:
- Index registration
- Encrypted withdrawal
- Access control (index ownership)
- Auditor decryption

## References

- [BabyJubJub Curve](https://eips.ethereum.org/EIPS/eip-2494)
- [ElGamal Encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [Circom Documentation](https://docs.circom.io/)
- [withdrawal.md](./withdrawal.md) - Original detailed specification

---

**Last Updated:** 2025-10-05
**Version:** 1.0
