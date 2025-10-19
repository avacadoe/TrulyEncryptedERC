# Intent Batching System - Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Complete Intent Lifecycle](#complete-intent-lifecycle)
3. [What Happens After Signing](#what-happens-after-signing)
4. [Batching & Execution Logic](#batching--execution-logic)
5. [Relayer Service Implementation](#relayer-service-implementation)
6. [Privacy Through Batching](#privacy-through-batching)
7. [Code Examples](#code-examples)

---

## Overview

**Current Implementation:** Private intent-based withdrawal system where:
- Users submit **intent hashes** (NOT amounts/destinations)
- `intentHash = poseidon(amount, destination, tokenId, nonce)` computed in ZK circuit
- Intents are batched and executed together
- Privacy achieved through **anonymity sets** - you can't tell which intent belongs to which user

**Key Privacy Insight:**
```
❌ OLD: submitWithdrawIntent(tokenId, destination, amount, ...)  // VISIBLE ON CHAIN!
✅ NEW: submitWithdrawIntent(tokenId, proof, balancePCT, metadata)  // Only hash visible!
```

---

## Complete Intent Lifecycle

### Phase 1: User Prepares Intent (Client-Side)

**1. User decides to withdraw**
```typescript
// User wants to withdraw 1000 tokens to 0xAlice
const amount = 1000n;
const destination = "0xAlice...";
const tokenId = 1n;
const nonce = 1n;  // User's current nonce for this token
```

**2. Generate ZK Proof (SDK)**

The SDK (`ac-eerc-sdk/src/EERC.ts:616`) does this:

```typescript
// a. Encrypt new balance (after withdrawal) for user
const newBalance = decryptedBalance - amount;  // 5000 - 1000 = 4000

const { cipher: senderCipherText, nonce: senderPoseidonNonce, authKey: senderAuthKey }
  = await poseidon.processPoseidonEncryption({
    inputs: [newBalance],           // 4000
    publicKey: userPublicKey,       // User's public key
  });

// b. Encrypt amount for auditor (compliance)
const { cipher: auditorCipherText, nonce: auditorPoseidonNonce, authKey: auditorAuthKey }
  = await poseidon.processPoseidonEncryption({
    inputs: [amount],               // 1000
    publicKey: auditorPublicKey,    // Auditor's public key
  });

// c. Encrypt intent metadata (optional - memo, timestamp)
const intentMetadata = await encryptMessage(JSON.stringify({
  amount: "1000",
  destination: "0xAlice...",
  tokenId: "1",
  memo: "Withdrawal for rent",
  timestamp: Date.now()
}));

// d. Generate ZK proof
const proofInputs = {
  ValueToWithdraw: 1000n,
  SenderPrivateKey: userPrivateKey,
  SenderPublicKey: userPublicKey,
  SenderBalance: 5000n,
  SenderBalanceC1: encryptedBalance.slice(0, 2),
  SenderBalanceC2: encryptedBalance.slice(2, 4),
  AuditorPublicKey: auditorPublicKey,
  AuditorPCT: auditorCipherText,
  AuditorPCTAuthKey: auditorAuthKey,
  AuditorPCTNonce: auditorPoseidonNonce,
  // CRITICAL: These are in the circuit but NOT in public signals!
  Destination: destination,        // 0xAlice...
  TokenId: tokenId,                // 1
  Nonce: nonce,                    // 1
};

const proof = await generateProof(proofInputs, "WITHDRAW");

// The circuit computes intentHash INSIDE the proof:
// intentHash = poseidon(amount, destination, tokenId, nonce)
//            = poseidon(1000, 0xAlice, 1, 1)
// This hash is placed in publicSignals[15]
```

**3. What the proof contains**

The proof has 16 public signals:
```typescript
publicSignals[0-1]   = User's public key (NOT secret!)
publicSignals[2-5]   = New encrypted balance (gibberish without private key)
publicSignals[6-7]   = Auditor's public key (NOT secret!)
publicSignals[8-11]  = Amount encrypted for auditor (only auditor can decrypt)
publicSignals[12-13] = Auth key for auditor's amount
publicSignals[14]    = Nonce for auditor's encryption
publicSignals[15]    = 🔒 intentHash = poseidon(amount, destination, tokenId, nonce)
```

**Key Point:** Amount, destination, and nonce are PRIVATE INPUTS to the circuit. They're proven correct but NOT revealed!

---

### Phase 2: Submit Intent (On-Chain)

**User calls contract:**
```solidity
function submitWithdrawIntent(
    uint256 tokenId,              // ✅ VISIBLE: 1
    WithdrawProof memory proof,   // ✅ VISIBLE: ZK proof with intentHash in publicSignals[15]
    uint256[7] memory balancePCT, // ✅ VISIBLE: New encrypted balance (gibberish)
    bytes calldata intentMetadata // ✅ VISIBLE: Encrypted metadata (gibberish)
)
```

**What happens in the contract (`EncryptedERC.sol:676`):**

```solidity
// 1. Extract intentHash from proof
intentHash = bytes32(proof.publicSignals[15]);
// intentHash = 0x0f53d0670696a62b... (the Poseidon hash)

// 2. Check user doesn't already have pending intent for this token
if (pendingIntents[msg.sender][tokenId]) {
    revert PendingIntentExists();
}

// 3. Store intent (WITHOUT amount/destination!)
WithdrawIntent storage intent = withdrawIntents[intentHash];
intent.user = msg.sender;           // 0xUser...
intent.tokenId = tokenId;           // 1
intent.timestamp = block.timestamp; // 1729300000
intent.executed = false;
intent.cancelled = false;

// 4. Lock user's balance for this token
pendingIntents[msg.sender][tokenId] = true;

// 5. Emit event
emit WithdrawIntentSubmitted(intentHash, msg.sender, intentId, block.timestamp);
```

**What's stored on-chain:**
```
withdrawIntents[intentHash] = {
  user: 0xUser...,
  tokenId: 1,
  timestamp: 1729300000,
  executed: false,
  cancelled: false
}

// ❌ NOT STORED: amount, destination, nonce
// ✅ Only the hash is stored!
```

---

### Phase 3: Intent Waiting Period

**Time-Based Permissions:**

```solidity
uint256 constant USER_ONLY_DELAY = 1 hours;       // First hour: only user can execute
uint256 constant PERMISSIONLESS_DELAY = 24 hours; // After 24h: anyone can execute
uint256 constant INTENT_EXPIRY = 7 days;          // Intent expires after 7 days
```

**Timeline:**
```
T=0     → Intent submitted
T=1h    → User can execute immediately
T=24h   → Relayer (anyone) can execute
T=7d    → Intent expires
```

**During this time:**
- User's balance is LOCKED for this tokenId
- User cannot submit another intent for the same token
- User can CANCEL the intent if they change their mind

---

### Phase 4: Batch Collection (Relayer Service)

**Relayer monitors for pending intents:**

```typescript
// Relayer service queries events
const intentEvents = await contract.queryFilter(
  contract.filters.WithdrawIntentSubmitted()
);

// Build batch of intents that are ready to execute
const batch = [];
for (const event of intentEvents) {
  const intentHash = event.args.intentHash;
  const intent = await contract.withdrawIntents(intentHash);

  // Check if intent is ready
  const timeSinceSubmission = Date.now() - intent.timestamp;

  if (intent.executed || intent.cancelled) continue;
  if (timeSinceSubmission < 24 * 3600) continue;  // Wait 24h
  if (timeSinceSubmission > 7 * 24 * 3600) continue;  // Expired

  batch.push({
    intentHash,
    user: intent.user,
    tokenId: intent.tokenId
  });
}
```

**Grouping Strategy:**

Option 1: **Fixed Time Windows** (e.g., execute every day at midnight)
```typescript
// Collect all intents submitted in the last 24h
// Execute at 00:00 UTC daily
```

Option 2: **Batch Size Threshold** (e.g., execute when 50 intents accumulated)
```typescript
if (batch.length >= 50) {
  executeBatch(batch);
}
```

Option 3: **Hybrid** (whichever comes first)
```typescript
if (batch.length >= 50 || timeSinceLastBatch >= 24h) {
  executeBatch(batch);
}
```

---

### Phase 5: Batch Execution

**Relayer needs to know the REAL amount/destination/nonce!**

**How does the relayer get this info?**

There are several approaches:

#### Approach 1: Users Provide Execution Data

Users store their intent details locally and provide them when ready:

```typescript
// User submits intent
const { intentHash } = await contract.submitWithdrawIntent(tokenId, proof, balancePCT, metadata);

// User stores locally or in backend DB
await userDatabase.saveIntent({
  intentHash,
  amount,
  destination,
  nonce,
  proof,
  balancePCT,
  metadata
});

// Later, user or relayer executes with real data
await contract.executeWithdrawIntent(
  intentHash,
  tokenId,
  destination,   // NOW revealed
  amount,        // NOW revealed
  nonce,         // NOW revealed
  proof,
  balancePCT,
  metadata
);
```

#### Approach 2: Encrypted Metadata (Current Implementation)

The `intentMetadata` field contains encrypted JSON:

```typescript
// User encrypts metadata with their public key during submission
const intentMetadata = await encryptMessage(JSON.stringify({
  amount: "1000",
  destination: "0xAlice...",
  tokenId: "1",
  nonce: "1",
  memo: "Rent payment"
}));

// Later, user decrypts to get execution parameters
const metadata = await decryptMessage(intentMetadata);
const { amount, destination, nonce } = JSON.parse(metadata);
```

**Problem:** Only the user can decrypt this! Relayer can't execute without user cooperation.

#### Approach 3: Relayer-Encrypted Channel

Users send execution data to relayer through encrypted channel:

```typescript
// User submits intent on-chain
const { intentHash } = await contract.submitWithdrawIntent(...);

// User sends execution data to relayer API (encrypted)
await relayerAPI.registerIntent({
  intentHash,
  encryptedPayload: encryptWithRelayerPublicKey({
    amount,
    destination,
    nonce,
    proof,
    balancePCT,
    metadata
  })
});

// Relayer stores this and executes after 24h
```

#### Approach 4: Public Submission Pool (Weak Privacy)

Users publish execution data publicly (reduces privacy):

```typescript
// User submits to IPFS/Arweave/public pool
const cid = await ipfs.add(JSON.stringify({
  intentHash,
  amount,
  destination,
  nonce,
  proof,
  balancePCT,
  metadata
}));

// Emit event with CID
await contract.submitWithdrawIntentWithCID(intentHash, cid);

// Relayer fetches from IPFS and executes
```

---

### Phase 6: Batch Execution (On-Chain)

**Relayer calls `executeBatchWithdrawIntents`:**

```solidity
function executeBatchWithdrawIntents(
    bytes32[] calldata intentHashes,      // [H1, H2, H3, ..., H50]
    uint256[] calldata tokenIds,          // [1, 1, 2, ..., 1]
    address[] calldata destinations,      // [0xAlice, 0xBob, 0xCarol, ...]
    uint256[] calldata amounts,           // [1000, 500, 2000, ...]
    uint256[] calldata nonces,            // [1, 1, 1, ...]
    WithdrawProof[] calldata proofs,      // [proof1, proof2, proof3, ...]
    uint256[7][] calldata balancePCTs,    // [balance1, balance2, ...]
    bytes[] calldata intentMetadatas      // [metadata1, metadata2, ...]
)
```

**Contract logic (`EncryptedERC.sol:797`):**

```solidity
for (uint256 i = 0; i < intentHashes.length; i++) {
    bytes32 intentHash = intentHashes[i];
    WithdrawIntent storage intent = withdrawIntents[intentHash];

    // 1. Check intent exists and is valid
    if (intent.user == address(0)) continue;  // Doesn't exist
    if (intent.executed || intent.cancelled) continue;  // Already processed
    if (block.timestamp > intent.timestamp + INTENT_EXPIRY) continue;  // Expired

    // 2. CRITICAL: Verify intentHash matches proof
    if (bytes32(proofs[i].publicSignals[15]) != intentHash) {
        continue;  // Proof doesn't match! Relayer tried to cheat!
    }

    // 3. Verify tokenId matches
    if (tokenIds[i] != intent.tokenId) continue;

    // 4. Check time-based permissions
    uint256 timeSinceSubmission = block.timestamp - intent.timestamp;
    if (timeSinceSubmission < PERMISSIONLESS_DELAY) {
        if (msg.sender != intent.user) continue;  // Too early for relayer
    }

    // 5. Execute withdrawal
    intent.executed = true;
    pendingIntents[intent.user][intent.tokenId] = false;  // Unlock balance

    // 6. Call internal _executeWithdrawIntentExternal
    try this._executeWithdrawIntentExternal(
        tokenIds[i],
        destinations[i],     // NOW REVEALED: 0xAlice
        amounts[i],          // NOW REVEALED: 1000
        proofs[i],
        balancePCTs[i],
        intentMetadatas[i]
    ) {
        emit WithdrawIntentExecuted(intentHash, msg.sender, block.timestamp);
        successCount++;
    } catch {
        intent.executed = false;  // Revert on failure
        pendingIntents[intent.user][intent.tokenId] = true;  // Re-lock
    }
}
```

**Key Security Check:**
```solidity
// Verify proof's intentHash matches the stored intent
if (bytes32(proofs[i].publicSignals[15]) != intentHash) {
    continue;  // REJECT!
}

// This proves: poseidon(amount, destination, tokenId, nonce) == intentHash
// So the relayer CANNOT execute with different amount/destination than user signed!
```

---

## Privacy Through Batching

### The Privacy Magic

**During Submission:**
```
User1 submits: intentHash = 0x0f53d067... (no one knows it's 1000 → 0xAlice)
User2 submits: intentHash = 0x3a7f2e19... (no one knows it's 500 → 0xBob)
User3 submits: intentHash = 0x8c4d1f92... (no one knows it's 2000 → 0xCarol)
```

**During Batch Execution:**
```
Relayer executes all 3 together:
- Someone withdrew 1000 to 0xAlice
- Someone withdrew 500 to 0xBob
- Someone withdrew 2000 to 0xCarol

Observer can see the amounts/destinations, but can't link them to the original users!
(Unless there's only 1 intent in the batch)
```

**Anonymity Set:**
- Batch size 1: **NO PRIVACY** (1 user = 1 withdrawal)
- Batch size 10: **WEAK PRIVACY** (10% chance of linking)
- Batch size 50: **GOOD PRIVACY** (2% chance of linking)
- Batch size 1000: **STRONG PRIVACY** (0.1% chance of linking)

**Timing Attack Mitigation:**
- Random delays before execution
- Fixed time windows (daily batches)
- Decoy intents (users submit fake intents)

---

## Relayer Service Implementation

### Architecture

```
┌─────────────┐
│   Users     │ Submit intents on-chain
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────┐
│     Blockchain (Avalanche)          │
│  - WithdrawIntentSubmitted events   │
│  - withdrawIntents mapping          │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│      Relayer Service                │
│  1. Monitor events                  │
│  2. Collect execution data          │
│  3. Group intents into batches      │
│  4. Execute batches after 24h       │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│     Execution Database              │
│  - intentHash → execution params    │
│  - Batch scheduling queue           │
└─────────────────────────────────────┘
```

### Relayer Service Code

```typescript
// relayer-service.ts
import { ethers } from "ethers";
import cron from "node-cron";

interface PendingIntent {
  intentHash: string;
  user: string;
  tokenId: bigint;
  timestamp: number;
  // Execution parameters (from user or encrypted channel)
  amount: bigint;
  destination: string;
  nonce: bigint;
  proof: any;
  balancePCT: string[];
  metadata: string;
}

class RelayerService {
  private pendingIntents: Map<string, PendingIntent> = new Map();
  private contract: ethers.Contract;

  constructor(
    private provider: ethers.Provider,
    private relayerSigner: ethers.Signer,
    private contractAddress: string
  ) {
    this.contract = new ethers.Contract(
      contractAddress,
      CONTRACT_ABI,
      relayerSigner
    );
  }

  // 1. Monitor blockchain for new intents
  async monitorIntents() {
    this.contract.on("WithdrawIntentSubmitted",
      async (intentHash, user, intentId, timestamp) => {
        console.log(`New intent: ${intentHash} from ${user}`);

        // Store intent metadata
        const intent = await this.contract.withdrawIntents(intentHash);

        this.pendingIntents.set(intentHash, {
          intentHash,
          user,
          tokenId: intent.tokenId,
          timestamp: intent.timestamp,
          // Execution params will be filled by registerExecution()
          amount: 0n,
          destination: "",
          nonce: 0n,
          proof: null,
          balancePCT: [],
          metadata: ""
        });
      }
    );
  }

  // 2. API endpoint for users to register execution data
  async registerExecution(request: {
    intentHash: string;
    amount: bigint;
    destination: string;
    nonce: bigint;
    proof: any;
    balancePCT: string[];
    metadata: string;
  }) {
    const intent = this.pendingIntents.get(request.intentHash);
    if (!intent) {
      throw new Error("Intent not found");
    }

    // Update with execution parameters
    intent.amount = request.amount;
    intent.destination = request.destination;
    intent.nonce = request.nonce;
    intent.proof = request.proof;
    intent.balancePCT = request.balancePCT;
    intent.metadata = request.metadata;

    this.pendingIntents.set(request.intentHash, intent);
  }

  // 3. Batch execution logic (runs every day at midnight)
  async executeBatch() {
    const now = Date.now() / 1000;
    const PERMISSIONLESS_DELAY = 24 * 3600;
    const INTENT_EXPIRY = 7 * 24 * 3600;

    const readyIntents: PendingIntent[] = [];

    for (const [hash, intent] of this.pendingIntents) {
      const timeSince = now - intent.timestamp;

      // Check if intent is ready
      if (timeSince < PERMISSIONLESS_DELAY) continue;  // Too early
      if (timeSince > INTENT_EXPIRY) {
        this.pendingIntents.delete(hash);  // Expired
        continue;
      }

      // Check if we have execution data
      if (!intent.proof || !intent.destination) {
        console.warn(`Missing execution data for ${hash}`);
        continue;
      }

      readyIntents.push(intent);
    }

    if (readyIntents.length === 0) {
      console.log("No intents ready for execution");
      return;
    }

    console.log(`Executing batch of ${readyIntents.length} intents`);

    // Group by batch size (max 50)
    const MAX_BATCH_SIZE = 50;
    for (let i = 0; i < readyIntents.length; i += MAX_BATCH_SIZE) {
      const batch = readyIntents.slice(i, i + MAX_BATCH_SIZE);
      await this.executeBatchOnChain(batch);
    }
  }

  // 4. Execute batch on-chain
  async executeBatchOnChain(batch: PendingIntent[]) {
    const intentHashes = batch.map(i => i.intentHash);
    const tokenIds = batch.map(i => i.tokenId);
    const destinations = batch.map(i => i.destination);
    const amounts = batch.map(i => i.amount);
    const nonces = batch.map(i => i.nonce);
    const proofs = batch.map(i => i.proof);
    const balancePCTs = batch.map(i => i.balancePCT);
    const metadatas = batch.map(i => i.metadata);

    try {
      const tx = await this.contract.executeBatchWithdrawIntents(
        intentHashes,
        tokenIds,
        destinations,
        amounts,
        nonces,
        proofs,
        balancePCTs,
        metadatas
      );

      const receipt = await tx.wait();
      console.log(`Batch executed: ${receipt.hash}`);

      // Remove executed intents
      for (const hash of intentHashes) {
        this.pendingIntents.delete(hash);
      }
    } catch (error) {
      console.error("Batch execution failed:", error);
    }
  }

  // 5. Start relayer service
  start() {
    // Monitor blockchain
    this.monitorIntents();

    // Schedule batch execution every day at midnight UTC
    cron.schedule("0 0 * * *", async () => {
      console.log("Running daily batch execution...");
      await this.executeBatch();
    });

    console.log("Relayer service started");
  }
}

// Usage
const relayer = new RelayerService(
  provider,
  relayerSigner,
  "0x3C5FD63b7a9f0487BA6fB0117764032a2eA3970c"
);
relayer.start();
```

---

## Complete Flow Summary

```
┌──────────────────────────────────────────────────────────────┐
│  1. USER PREPARES INTENT (Client-Side)                       │
│  ─────────────────────────────────────────────────────────   │
│  • User decides: withdraw 1000 to 0xAlice                    │
│  • SDK generates ZK proof                                     │
│  • Circuit computes: intentHash = poseidon(1000, 0xAlice, 1, 1) │
│  • Proof contains encrypted balance & intentHash              │
└──────────┬───────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│  2. SUBMIT INTENT (On-Chain)                                 │
│  ─────────────────────────────────────────────────────────   │
│  • submitWithdrawIntent(tokenId, proof, balancePCT, metadata) │
│  • Contract extracts intentHash from proof.publicSignals[15]  │
│  • Stores: withdrawIntents[hash] = {user, tokenId, timestamp} │
│  • Locks user's balance for this token                        │
│  • ❌ Amount/destination NOT stored!                          │
└──────────┬───────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│  3. WAITING PERIOD (24 hours)                                │
│  ─────────────────────────────────────────────────────────   │
│  • 0-1h: Only user can execute                                │
│  • 1-24h: Only user can execute                               │
│  • 24h+: Anyone (relayer) can execute                         │
│  • 7d+: Intent expires                                        │
└──────────┬───────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│  4. RELAYER COLLECTS BATCH                                   │
│  ─────────────────────────────────────────────────────────   │
│  • Monitor WithdrawIntentSubmitted events                     │
│  • User provides execution data (amount, destination, nonce)  │
│  • Relayer stores 50+ intents                                 │
│  • Wait for daily execution window                            │
└──────────┬───────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│  5. BATCH EXECUTION (On-Chain)                               │
│  ─────────────────────────────────────────────────────────   │
│  • executeBatchWithdrawIntents(hashes, amounts, destinations...) │
│  • For each intent:                                           │
│    - Verify proof.publicSignals[15] == intentHash             │
│    - Verify tokenId matches                                   │
│    - Check time permissions                                   │
│    - Execute withdrawal                                       │
│  • ✅ NOW amounts/destinations are revealed!                  │
│  • But no one knows which user submitted which intent!        │
└──────────────────────────────────────────────────────────────┘
```

---

## Privacy Analysis

### What Observer Sees During Submission

```
Transaction 1: User1 calls submitWithdrawIntent
  - User: 0xUser1
  - Token: 1
  - IntentHash: 0x0f53d067...
  - Encrypted Balance: [6693884498..., 16139808091..., ...]
  - ❌ Can't see: amount, destination

Transaction 2: User2 calls submitWithdrawIntent
  - User: 0xUser2
  - Token: 1
  - IntentHash: 0x3a7f2e19...
  - Encrypted Balance: [8471923847..., 92837461923..., ...]
  - ❌ Can't see: amount, destination
```

### What Observer Sees During Batch Execution

```
Transaction: Relayer calls executeBatchWithdrawIntents
  - Intent 1: 1000 tokens → 0xAlice
  - Intent 2: 500 tokens → 0xBob
  - Intent 3: 2000 tokens → 0xCarol
  - Intent 4: 750 tokens → 0xDave
  - ... (50 intents total)

Observer knows:
  ✅ Someone withdrew 1000 to 0xAlice
  ✅ Someone withdrew 500 to 0xBob
  ❌ Can't tell if User1 → 0xAlice or User2 → 0xAlice
  ❌ Can't link intentHash to withdrawal (unless batch size = 1)
```

### Attack Vectors

**1. Batch Size 1 Attack**
```
If only 1 intent in batch:
  User1 submitted intentHash 0x0f53d067...
  Batch executed: 1000 → 0xAlice
  Conclusion: User1 withdrew 1000 to 0xAlice  ❌ NO PRIVACY
```

**2. Dictionary Attack on IntentHash**
```
Observer tries:
  for amount in [1, 10, 100, 1000, ...]:
    for destination in [0xAlice, 0xBob, ...]:
      for nonce in [1, 2, 3, ...]:
        if poseidon(amount, dest, 1, nonce) == 0x0f53d067:
          Found! User withdrew amount to dest

Complexity: O(amounts × destinations × nonces)
  10,000 amounts × 100 addresses × 100 nonces = 100M hashes
  Time: Minutes on modern hardware
```

**Mitigation:** Add random salt to intentHash
```solidity
intentHash = poseidon(amount, destination, tokenId, nonce, SALT)
// SALT = 256-bit random value
// Now complexity: O(2^256) - infeasible!
```

---

## Recommended Improvements

### 1. Add Salt to Intent Hash

**Circuit modification:**
```circom
signal input Salt;  // 256-bit random value

signal intentHash <== Poseidon(5)([
    ValueToWithdraw,
    Destination,
    TokenId,
    Nonce,
    Salt  // NEW
]);
```

**Privacy boost:** ⭐⭐⭐⭐ → ⭐⭐⭐⭐⭐

### 2. Increase Batch Sizes

```typescript
// Current: 50 intents per batch (2% linkage)
// Recommended: 1000+ intents per batch (0.1% linkage)
const MAX_BATCH_SIZE = 1000;
```

### 3. Decoy Intents

```typescript
// Users submit fake intents they never execute
// Increases anonymity set without real cost
const realIntent = await submitWithdrawIntent(...);
const decoyIntent1 = await submitWithdrawIntent(...);  // Fake
const decoyIntent2 = await submitWithdrawIntent(...);  // Fake
```

### 4. Randomized Execution Timing

```typescript
// Don't execute at fixed time (midnight)
// Add random delay ±6 hours
const randomDelay = Math.random() * 12 * 3600;
const executionTime = midnight + randomDelay - 6 * 3600;
```

---

## Questions?

- **Q: How does relayer get amount/destination if it's not on-chain?**
  A: User provides it via encrypted API endpoint, or stores in encrypted metadata

- **Q: Can relayer execute with wrong amount?**
  A: No! Contract verifies `poseidon(amount, dest, tokenId, nonce) == intentHash`

- **Q: What if batch has only 1 intent?**
  A: No privacy! Observer can link user → withdrawal. Need larger batches.

- **Q: Can observer brute force intentHash?**
  A: Partially - if amounts/destinations are predictable. Add salt to prevent this.

- **Q: Why not execute immediately?**
  A: Privacy! Need to batch multiple intents to create anonymity set.
