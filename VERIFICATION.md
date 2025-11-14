# Manual Verification: Permissionless Intent Execution Fix

## Overview
This document provides manual verification that the fix for permissionless withdrawal intent execution is correct, even without running tests.

## The Bug (Before Fix)

### Code Path 1: Batch Execution
```
1. relayer calls executeBatchWithdrawIntents(...)
   msg.sender = relayer

2. For each intent:
   this._executeWithdrawIntentExternal(...)
   ↓ [external call changes msg.sender]
   msg.sender = address(this) (the contract)

3. _executeWithdrawWithIntent(...) called
   address from = msg.sender;  // ❌ from = address(this)

4. _validatePublicKey(from, proof.publicSignals[0:1])
   ↓
   Tries to validate: contract's public key == user's public key from proof
   ❌ FAIL: These don't match!
```

### Code Path 2: Relayer Execution After 24h
```
1. relayer calls executeWithdrawIntent(intentHash, ...)
   msg.sender = relayer

2. _executeWithdrawWithIntent(...) called
   address from = msg.sender;  // ❌ from = relayer

3. _validatePublicKey(from, proof.publicSignals[0:1])
   ↓
   Tries to validate: relayer's public key == user's public key from proof
   ❌ FAIL: These don't match!
```

## The Fix (After)

### Modified Function Signature
```solidity
// BEFORE
function _executeWithdrawWithIntent(
    uint256 tokenId,
    address destination,
    uint256 amount,
    WithdrawProof memory proof,
    uint256[7] memory balancePCT,
    bytes memory intentMetadata
) internal {
    address from = msg.sender;  // ❌ WRONG
    ...
}

// AFTER
function _executeWithdrawWithIntent(
    address user,  // ✅ NEW: Explicit parameter
    uint256 tokenId,
    address destination,
    uint256 amount,
    WithdrawProof memory proof,
    uint256[7] memory balancePCT,
    bytes memory intentMetadata
) internal {
    address from = user;  // ✅ Use passed parameter
    ...
}
```

### Code Path 1: Batch Execution (Fixed)
```
1. relayer calls executeBatchWithdrawIntents(...)
   msg.sender = relayer

2. For each intent:
   Load: intent = withdrawIntents[intentHash]
   Get: user = intent.user  // ✅ Original user who created intent

   this._executeWithdrawIntentExternal(
       intent.user,  // ✅ Pass explicit user
       ...
   )

3. _executeWithdrawIntentExternal receives:
   user = intent.user  // ✅ Correct user

   Forwards to: _executeWithdrawWithIntent(user, ...)

4. _executeWithdrawWithIntent receives:
   address from = user;  // ✅ from = original intent creator

5. _validatePublicKey(from, proof.publicSignals[0:1])
   ↓
   Validates: intent.user's public key == intent.user's public key from proof
   ✅ SUCCESS: These match!
```

### Code Path 2: Relayer Execution After 24h (Fixed)
```
1. relayer calls executeWithdrawIntent(intentHash, ...)
   msg.sender = relayer

2. Load intent from storage:
   intent = withdrawIntents[intentHash]
   user = intent.user  // ✅ Original user who created intent

3. Time gate checks:
   timeSinceSubmission >= PERMISSIONLESS_DELAY (24h)
   ✅ Anyone can execute

4. _executeWithdrawWithIntent(
       intent.user,  // ✅ Pass original user
       ...
   )

5. _executeWithdrawWithIntent receives:
   address from = user;  // ✅ from = original intent creator

6. _validatePublicKey(from, proof.publicSignals[0:1])
   ↓
   Validates: intent.user's public key == intent.user's public key from proof
   ✅ SUCCESS: These match!
```

### Code Path 3: Direct User Call (Still Works)
```
1. user calls withdrawWithIntent(tokenId, destination, amount, ...)
   msg.sender = user

2. _executeWithdrawWithIntent(
       msg.sender,  // ✅ Pass msg.sender for direct calls
       ...
   )

3. _executeWithdrawWithIntent receives:
   address from = user;  // ✅ from = msg.sender (the user)

4. _validatePublicKey(from, proof.publicSignals[0:1])
   ↓
   Validates: user's public key == user's public key from proof
   ✅ SUCCESS: These match!
```

## Key Test Cases (from test/EncryptedERC-TwoStepIntent.ts)

### Test 1: Batch Execution (Line 967)
**Test**: "should execute multiple intents in batch (PRIVACY VIA ANONYMITY SET!)"

**What it tests:**
1. User0 submits intent (amount/destination hidden)
2. User1 submits intent (amount/destination hidden)
3. Wait 24 hours
4. Relayer executes both in batch
5. Expects: Both withdrawals succeed, users receive tokens

**Why it works now:**
- Batch calls `_executeWithdrawIntentExternal(intent.user, ...)` for each intent
- Each intent validates against its correct user's public key
- No confusion between relayer and intent creators

### Test 2: Single Intent Execution (Line 299)
**Test**: "should execute a withdraw intent after 24 hours by relayer"

**What it tests:**
1. User submits intent
2. Wait 24 hours
3. Different relayer executes intent
4. Expects: Withdrawal succeeds

**Why it works now:**
- executeWithdrawIntent passes `intent.user` to internal function
- Validates correct user's public key, not relayer's

### Test 3: Direct Withdrawal (Line 142)
**Test**: "should successfully withdraw with encrypted intent metadata"

**What it tests:**
1. User calls withdrawWithIntent directly
2. Expects: Immediate withdrawal succeeds

**Why it still works:**
- withdrawWithIntent passes `msg.sender` to internal function
- Validates caller's public key correctly

## Proof Validation Logic

The critical validation in _executeWithdrawWithIntent is:

```solidity
// Line 1579
_validatePublicKey(from, [publicInputs[0], publicInputs[1]]);
```

Which calls:
```solidity
function _validatePublicKey(
    address user,
    uint256[2] memory providedPublicKey
) internal view {
    uint256[2] memory userPublicKey = registrar.getUserPublicKey(user);

    if (
        userPublicKey[0] != providedPublicKey[0] ||
        userPublicKey[1] != providedPublicKey[1]
    ) {
        revert InvalidProof();
    }
}
```

**The fix ensures:**
- `user` parameter = intent creator (from storage)
- `providedPublicKey` = proof public signals (from ZK proof)
- These MUST match because the proof was generated by the intent creator

**Before fix:**
- `user` parameter = msg.sender (could be relayer or contract)
- `providedPublicKey` = proof public signals (from intent creator)
- These DON'T match → InvalidProof revert

## Changes Summary

### Modified Functions (5 total)

1. **_executeWithdrawWithIntent** (Line 1557)
   - Added `address user` parameter
   - Changed `address from = msg.sender` → `address from = user`

2. **executeWithdrawIntent** (Line 728)
   - Now passes `intent.user` to _executeWithdrawWithIntent

3. **_executeWithdrawIntentExternal** (Line 910)
   - Added `address user` parameter
   - Forwards to _executeWithdrawWithIntent

4. **executeBatchWithdrawIntents** (Line 797)
   - Now passes `intent.user` for each execution

5. **withdrawWithIntent** (Line 649)
   - Now passes `msg.sender` to _executeWithdrawWithIntent

### Lines Changed
- contracts/EncryptedERC.sol:662 (withdrawWithIntent call)
- contracts/EncryptedERC.sol:772-780 (executeWithdrawIntent call)
- contracts/EncryptedERC.sol:865-873 (batch execution call)
- contracts/EncryptedERC.sol:910-920 (external wrapper signature)
- contracts/EncryptedERC.sol:1557-1566 (internal function signature)

## Verification Result

✅ **VERIFIED**: The fix is logically correct and will:
1. Enable permissionless execution after 24 hours
2. Fix batch execution for anonymity sets
3. Maintain compatibility with direct user calls
4. Correctly validate ZK proofs against intent creators

## Network/Compilation Issues

**Note**: Cannot run automated tests due to:
- Network restrictions blocking Solidity compiler download (403 from soliditylang.org)
- Network restrictions blocking Circom compiler download

**Recommendation**: Run tests on local machine with proper network access to confirm this manual verification.
