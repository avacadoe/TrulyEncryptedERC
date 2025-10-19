# SDK & Contract Roadmap for Frontend Integration

## SDK Status Assessment

### ✅ What's Already Working

**Core Operations (Ready)**:
- ✅ `register()` - User registration
- ✅ `privateMint()` - Mint private tokens (standalone)
- ✅ `privateBurn()` - Burn private tokens (standalone)
- ✅ `transfer()` - Private transfers between users
- ✅ `deposit()` - Convert ERC20 → eERC (converter)
- ✅ `withdraw()` - Direct withdrawal (converter)
- ✅ `withdrawWithIntent()` - Submit intent (calls old contract method)

**Utilities (Ready)**:
- ✅ `fetchPublicKey()` - Get user's public key
- ✅ `fetchTokenId()` - Get token ID from address
- ✅ `getEncryptedBalance()` - Fetch encrypted balance
- ✅ `decryptBalance()` - Decrypt balance client-side
- ✅ `auditorDecrypt()` - Auditor functionality

**Version**: `2.0.61`
**Package**: `@avalabs/ac-eerc-sdk`

---

## 🚨 Critical SDK Tasks for Frontend Integration

### Priority 1: Intent System Methods (MISSING)

The SDK currently has `withdrawWithIntent()` but it calls the OLD contract method. We need NEW methods for the private intent system:

#### 1.1 `submitWithdrawIntent()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🔴 CRITICAL

```typescript
async submitWithdrawIntent(
  amount: bigint,
  destination: string,
  tokenId: bigint,
  nonce: bigint,
  encryptedBalance: bigint[],
  decryptedBalance: bigint,
  auditorPublicKey: bigint[],
  tokenAddress: string,
  memo?: string
): Promise<{
  intentHash: string;
  transactionHash: string;
  executionData: {
    amount: bigint;
    destination: string;
    nonce: bigint;
    proof: any;
    balancePCT: string[];
    metadata: string;
  };
}>
```

**What it needs to do**:
1. Generate ZK proof with NEW circuit (withdrawIntent.circom)
2. Circuit computes intentHash = poseidon(amount, destination, tokenId, nonce)
3. Call contract: `submitWithdrawIntent(tokenId, proof, balancePCT, metadata)`
4. Return intentHash + execution data for later use
5. Store execution data locally or in backend

**Frontend will need**:
- Form to input amount + destination
- Loading state during proof generation (~5-10 seconds)
- Display intentHash after submission
- Store executionData for batch execution

---

#### 1.2 `executeWithdrawIntent()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🔴 CRITICAL

```typescript
async executeWithdrawIntent(
  intentHash: string,
  tokenId: bigint,
  destination: string,
  amount: bigint,
  nonce: bigint,
  proof: any,
  balancePCT: string[],
  metadata: string
): Promise<{ transactionHash: string }>
```

**What it needs to do**:
1. Take previously stored execution data
2. Call contract: `executeWithdrawIntent(intentHash, tokenId, destination, amount, nonce, proof, balancePCT, metadata)`
3. Contract verifies proof.publicSignals[15] == intentHash
4. Execute withdrawal

**Frontend will need**:
- List of pending intents
- Execute button (available after 1 hour for user)
- Status indicator (waiting / executable / expired)

---

#### 1.3 `executeBatchWithdrawIntents()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🟡 MEDIUM (for relayer, not users)

```typescript
async executeBatchWithdrawIntents(
  intents: Array<{
    intentHash: string;
    tokenId: bigint;
    destination: string;
    amount: bigint;
    nonce: bigint;
    proof: any;
    balancePCT: string[];
    metadata: string;
  }>
): Promise<{ transactionHash: string; successCount: number }>
```

**What it needs to do**:
1. Take array of intent execution data
2. Call contract batch method
3. Return success count

**Frontend will need** (relayer dashboard):
- Admin panel showing pending intents
- Batch execution button
- Status of each intent in batch

---

#### 1.4 `cancelWithdrawIntent()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🟢 LOW (nice to have)

```typescript
async cancelWithdrawIntent(
  intentHash: string
): Promise<{ transactionHash: string }>
```

**What it needs to do**:
1. Call contract: `cancelWithdrawIntent(intentHash)`
2. Only intent creator can cancel
3. Unlocks user's balance

**Frontend will need**:
- Cancel button on pending intents
- Confirmation dialog

---

### Priority 2: Helper Methods for Intent System

#### 2.1 `getPendingIntents()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🟡 MEDIUM

```typescript
async getPendingIntents(
  userAddress: string
): Promise<Array<{
  intentHash: string;
  tokenId: bigint;
  timestamp: number;
  executed: boolean;
  cancelled: boolean;
  isExecutable: boolean; // true if > 1 hour passed
  isExpired: boolean;    // true if > 7 days passed
}>>
```

**What it needs to do**:
1. Query contract events: `WithdrawIntentSubmitted`
2. Filter by user address
3. Check status of each intent
4. Calculate time-based permissions

**Frontend will need**:
- Intent history table
- Status badges (pending / executable / expired)

---

#### 2.2 `getIntentStatus()` - NEW METHOD
**Status**: ❌ MISSING
**Priority**: 🟡 MEDIUM

```typescript
async getIntentStatus(
  intentHash: string
): Promise<{
  exists: boolean;
  user: string;
  tokenId: bigint;
  timestamp: number;
  executed: boolean;
  cancelled: boolean;
  canUserExecute: boolean;
  canRelayerExecute: boolean;
  isExpired: boolean;
  timeUntilExecutable: number; // seconds
}>
```

**What it needs to do**:
1. Query contract: `withdrawIntents(intentHash)`
2. Calculate time-based permissions
3. Return detailed status

**Frontend will need**:
- Intent detail page
- Countdown timer
- Execute button enabled/disabled based on status

---

#### 2.3 `computeIntentHash()` - UTILITY METHOD
**Status**: ❌ MISSING
**Priority**: 🟢 LOW (nice to have)

```typescript
computeIntentHash(
  amount: bigint,
  destination: string,
  tokenId: bigint,
  nonce: bigint
): string
```

**What it needs to do**:
1. Use poseidon-lite to compute hash client-side
2. Helps verify intentHash without generating full proof

**Frontend will need**:
- Verification tool
- Debug panel

---

### Priority 3: Storage/State Management

#### 3.1 Local Storage for Execution Data
**Status**: ❌ MISSING
**Priority**: 🔴 CRITICAL

```typescript
// Store execution data after submitting intent
saveIntentExecutionData(intentHash: string, executionData: ExecutionData): void

// Retrieve when ready to execute
getIntentExecutionData(intentHash: string): ExecutionData | null

// List all stored intents
getAllStoredIntents(): Array<{ intentHash: string; executionData: ExecutionData }>
```

**Why needed**:
- User needs amount/destination/nonce to execute intent
- This data is NOT stored on-chain (privacy!)
- Must be stored locally or in backend database

**Frontend will need**:
- LocalStorage or IndexedDB integration
- Export/backup functionality
- Import functionality (for wallet recovery)

---

#### 3.2 Backend API Integration (Optional)
**Status**: ❌ NOT STARTED
**Priority**: 🟡 MEDIUM

```typescript
// For users who want cloud backup
async syncIntentsToBackend(userAddress: string): Promise<void>
async fetchIntentsFromBackend(userAddress: string): Promise<void>
```

**Why needed**:
- Users might lose local storage
- Multi-device support
- Relayer needs to collect intents from users

---

### Priority 4: Circuit Updates

#### 4.1 Update Proof Generation for New Circuit
**Status**: ⚠️ PARTIAL (circuit exists, SDK needs update)
**Priority**: 🔴 CRITICAL

**Current**: SDK uses `withdraw.circom`
**Needed**: SDK should use `withdrawIntent.circom` for intent submissions

**Changes needed in SDK**:
```typescript
// In generateProof method
if (operation === "WITHDRAW_INTENT") {
  // Use withdrawIntent.circom circuit
  // Public inputs include IntentHash
  // Circuit verifies: poseidon(amount, dest, tokenId, nonce) == IntentHash
}
```

---

### Priority 5: Event Monitoring

#### 5.1 Listen for Intent Events
**Status**: ❌ MISSING
**Priority**: 🟡 MEDIUM

```typescript
// Listen for new intents
onWithdrawIntentSubmitted(
  callback: (intentHash: string, user: string, intentId: number, timestamp: number) => void
): void

// Listen for executions
onWithdrawIntentExecuted(
  callback: (intentHash: string, executor: string, timestamp: number) => void
): void

// Listen for cancellations
onWithdrawIntentCancelled(
  callback: (intentHash: string, user: string, timestamp: number) => void
): void
```

**Frontend will need**:
- Real-time updates in UI
- Notifications when intent is executed
- Toast messages

---

## 📋 Contract Improvements

### Priority 1: Security & Privacy Enhancements

#### 1.1 Add Salt to IntentHash
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🔴 CRITICAL
**Impact**: Security improvement from ⭐⭐⭐⭐ to ⭐⭐⭐⭐⭐

**Current**:
```circom
intentHash = Poseidon(4)([amount, destination, tokenId, nonce])
```

**Recommended**:
```circom
signal input Salt; // 256-bit random value

intentHash = Poseidon(5)([amount, destination, tokenId, nonce, Salt])
```

**Benefits**:
- Prevents dictionary attacks completely
- Makes intentHash impossible to brute force
- Cost: Minimal (one extra field)

**Tasks**:
- [ ] Update `withdrawIntent.circom` to include Salt
- [ ] Recompile circuit
- [ ] Update SDK to generate random salt
- [ ] Update contract to handle new public signals
- [ ] Redeploy contracts

---

#### 1.2 Increase MAX_BATCH_SIZE
**Status**: ✅ IMPLEMENTED (50)
**Priority**: 🟡 MEDIUM
**Recommendation**: Increase to 100-200

**Current**: `MAX_BATCH_SIZE = 50`
**Recommended**: `MAX_BATCH_SIZE = 200`

**Benefits**:
- Larger anonymity sets (0.5% vs 2% linkage)
- Better privacy through batching
- More efficient gas usage

**Tasks**:
- [ ] Update contract constant
- [ ] Test gas limits (ensure < block gas limit)
- [ ] Redeploy

---

#### 1.3 Add Intent Metadata Encryption Key Rotation
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

**Current**: Metadata encrypted with user's public key
**Recommended**: Support multiple encryption keys

**Benefits**:
- Key rotation for long-term security
- Multi-device support
- Recovery mechanisms

---

### Priority 2: Gas Optimizations

#### 2.1 Optimize Batch Execution Gas Usage
**Status**: ⚠️ NEEDS TESTING
**Priority**: 🟡 MEDIUM

**Current gas cost**: ~200k per intent in batch
**Target**: < 150k per intent

**Optimization ideas**:
- Cache verifier checks
- Batch verify proofs (if possible)
- Use assembly for hot paths
- Reduce storage writes

**Tasks**:
- [ ] Run gas profiler on batch execution
- [ ] Identify hot spots
- [ ] Implement optimizations
- [ ] Test gas savings

---

#### 2.2 Use Transient Storage (EIP-1153) for Temp Data
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW (requires Cancun fork)

**Benefits**:
- Cheaper temporary storage
- Better for batch processing

---

### Priority 3: User Experience Improvements

#### 3.1 Add Intent Expiry Extension
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

**Current**: Intent expires after 7 days (fixed)
**Recommended**: Allow user to extend expiry

```solidity
function extendIntentExpiry(bytes32 intentHash) external {
    require(msg.sender == withdrawIntents[intentHash].user);
    withdrawIntents[intentHash].timestamp = block.timestamp;
}
```

**Benefits**:
- Users don't lose intents if they forget
- More flexible UX

---

#### 3.2 Partial Intent Execution
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

**Current**: Intent is all-or-nothing
**Recommended**: Allow splitting large withdrawals

**Benefits**:
- Withdraw in smaller chunks
- Better privacy (more intents = larger anonymity set)

**Challenges**:
- Complex proof system
- Nonce management

---

#### 3.3 Intent Scheduling
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

**Recommended**: Allow user to specify earliest execution time

```solidity
struct WithdrawIntent {
    address user;
    uint256 tokenId;
    uint256 timestamp;
    uint256 earliestExecution; // NEW
    bool executed;
    bool cancelled;
}
```

**Benefits**:
- Dollar-cost averaging
- Scheduled payments
- Privacy through timing randomization

---

### Priority 4: Monitoring & Analytics

#### 4.1 Add More Events
**Status**: ⚠️ PARTIAL
**Priority**: 🟡 MEDIUM

**Current events**:
- ✅ WithdrawIntentSubmitted
- ✅ WithdrawIntentExecuted
- ✅ WithdrawIntentCancelled

**Recommended new events**:
```solidity
event IntentExpired(bytes32 indexed intentHash);
event BatchExecutionFailed(bytes32 indexed intentHash, string reason);
event IntentExpiryExtended(bytes32 indexed intentHash, uint256 newTimestamp);
```

**Benefits**:
- Better monitoring
- Failed intent tracking
- Analytics for relayer optimization

---

#### 4.2 Add Batch Execution Statistics
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

```solidity
mapping(uint256 => BatchStats) public batchHistory;

struct BatchStats {
    uint256 timestamp;
    uint256 totalIntents;
    uint256 successfulIntents;
    uint256 failedIntents;
    address executor;
}
```

**Benefits**:
- Track relayer performance
- Analytics dashboard
- Privacy metrics (batch sizes over time)

---

### Priority 5: Relayer Infrastructure

#### 5.1 Relayer Incentives
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟡 MEDIUM

**Current**: No incentive for relayers to execute batches
**Recommended**: Add relayer fee mechanism

```solidity
uint256 public relayerFeePerIntent = 0.001 ether;

function executeBatchWithdrawIntents(...) external {
    // ... existing logic

    // Pay relayer
    uint256 totalFee = successCount * relayerFeePerIntent;
    payable(msg.sender).transfer(totalFee);
}
```

**Benefits**:
- Sustainable relayer network
- Guaranteed batch execution
- Decentralized operation

**Challenges**:
- Fee source (protocol treasury? user fees?)
- Fee calculation

---

#### 5.2 Relayer Registration
**Status**: ❌ NOT IMPLEMENTED
**Priority**: 🟢 LOW

**Recommended**: Track approved relayers

```solidity
mapping(address => bool) public approvedRelayers;
bool public permissionlessExecution = true;

modifier onlyRelayer() {
    if (!permissionlessExecution) {
        require(approvedRelayers[msg.sender], "NotApprovedRelayer");
    }
    _;
}
```

**Benefits**:
- Optional permissioned phase during launch
- Quality control
- Transition to permissionless over time

---

## 📊 Summary Tables

### SDK Tasks Priority Matrix

| Task | Priority | Effort | Impact | Status |
|------|----------|--------|--------|--------|
| submitWithdrawIntent() | 🔴 Critical | High | High | ❌ Missing |
| executeWithdrawIntent() | 🔴 Critical | Medium | High | ❌ Missing |
| Storage for execution data | 🔴 Critical | Medium | High | ❌ Missing |
| Update proof generation | 🔴 Critical | High | High | ⚠️ Partial |
| getPendingIntents() | 🟡 Medium | Medium | Medium | ❌ Missing |
| getIntentStatus() | 🟡 Medium | Low | Medium | ❌ Missing |
| executeBatch() | 🟡 Medium | Medium | Medium | ❌ Missing |
| Event listeners | 🟡 Medium | Low | Medium | ❌ Missing |
| cancelWithdrawIntent() | 🟢 Low | Low | Low | ❌ Missing |
| computeIntentHash() | 🟢 Low | Low | Low | ❌ Missing |

### Contract Improvements Priority Matrix

| Improvement | Priority | Effort | Impact | Status |
|-------------|----------|--------|--------|--------|
| Add salt to intentHash | 🔴 Critical | High | Very High | ❌ Not done |
| Increase MAX_BATCH_SIZE | 🟡 Medium | Low | Medium | ✅ Can adjust |
| Gas optimizations | 🟡 Medium | High | Medium | ⚠️ Needs testing |
| More events | 🟡 Medium | Low | Medium | ⚠️ Partial |
| Relayer incentives | 🟡 Medium | Medium | High | ❌ Not done |
| Intent expiry extension | 🟢 Low | Low | Low | ❌ Not done |
| Batch statistics | 🟢 Low | Low | Low | ❌ Not done |
| Intent scheduling | 🟢 Low | Medium | Low | ❌ Not done |
| Partial execution | 🟢 Low | Very High | Medium | ❌ Not done |

---

## 🚀 Recommended Implementation Order

### Phase 1: MVP for Frontend (1-2 weeks)

**Goal**: Basic intent submission and execution working in frontend

1. **SDK**: Add `submitWithdrawIntent()` method
2. **SDK**: Add `executeWithdrawIntent()` method
3. **SDK**: Add local storage for execution data
4. **SDK**: Update proof generation for withdrawIntent circuit
5. **Frontend**: Create intent submission UI
6. **Frontend**: Create pending intents list
7. **Frontend**: Add execute button with time check
8. **Testing**: E2E test of full flow

### Phase 2: Enhanced UX (1 week)

**Goal**: Better monitoring and user experience

1. **SDK**: Add `getPendingIntents()` method
2. **SDK**: Add `getIntentStatus()` method
3. **SDK**: Add event listeners
4. **Frontend**: Real-time intent updates
5. **Frontend**: Status indicators and countdown timers
6. **Frontend**: Toast notifications

### Phase 3: Security Hardening (2 weeks)

**Goal**: Maximum security and privacy

1. **Circuit**: Add salt to intentHash
2. **Circuit**: Recompile and test
3. **SDK**: Update to use new circuit
4. **Contract**: Deploy new version with salt support
5. **Testing**: Full security audit of new system
6. **Contract**: Increase MAX_BATCH_SIZE to 200

### Phase 4: Relayer Infrastructure (1-2 weeks)

**Goal**: Decentralized batch execution

1. **SDK**: Add `executeBatchWithdrawIntents()` method
2. **Contract**: Add relayer fee mechanism
3. **Backend**: Build relayer service (from docs/INTENT_BATCHING_SYSTEM.md)
4. **Backend**: Add scheduling (daily batches)
5. **Backend**: Add monitoring dashboard
6. **Testing**: Test batch execution with 50+ intents

### Phase 5: Polish & Optimization (ongoing)

**Goal**: Production-ready system

1. **Contract**: Gas optimizations
2. **Contract**: Additional events
3. **SDK**: Backend sync for execution data
4. **Frontend**: Advanced features (cancel, export/import)
5. **Docs**: User guides and tutorials
6. **Marketing**: Privacy metrics and analytics

---

## 📝 Notes for Frontend Team

### What Frontend Can Start Building Now

**Without waiting for SDK updates**:

1. **UI/UX Design**:
   - Intent submission form mockups
   - Pending intents list design
   - Status indicators and badges
   - Countdown timers
   - Execute button states

2. **Component Structure**:
   - `<IntentSubmission />` component skeleton
   - `<PendingIntents />` list component
   - `<IntentCard />` item component
   - `<ExecuteButton />` with time logic (can mock SDK)

3. **State Management**:
   - Redux/Zustand store for intents
   - Local storage integration
   - Event listener setup

4. **Mock Data**:
   - Create mock intent objects
   - Test UI with fake data
   - Build complete flow with placeholders

### SDK Integration Points

Once SDK is updated, frontend will need to:

```typescript
import { EERC } from '@avalabs/ac-eerc-sdk';

// Submit intent
const { intentHash, executionData } = await eerc.submitWithdrawIntent(
  amount,
  destination,
  tokenId,
  nonce,
  encryptedBalance,
  decryptedBalance,
  auditorPublicKey,
  tokenAddress,
  memo
);

// Store execution data locally
localStorage.setItem(`intent-${intentHash}`, JSON.stringify(executionData));

// Later, execute
const storedData = JSON.parse(localStorage.getItem(`intent-${intentHash}`));
await eerc.executeWithdrawIntent(
  intentHash,
  tokenId,
  storedData.destination,
  storedData.amount,
  storedData.nonce,
  storedData.proof,
  storedData.balancePCT,
  storedData.metadata
);
```

---

## Questions to Resolve

1. **Execution Data Storage**: Local storage or backend API? Or both?
2. **Relayer Economics**: Who pays relayer fees? Protocol? Users?
3. **Circuit Salt**: Random per-intent or deterministic from user's private key?
4. **Batch Timing**: Daily at midnight? Or threshold-based (50 intents)?
5. **Frontend Framework**: React hooks for intent management?
6. **Testing Strategy**: Testnet deployment plan?
7. **Migration Path**: How to handle existing withdrawWithIntent users?
