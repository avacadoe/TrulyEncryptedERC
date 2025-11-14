# CLAUDE.md - AI Assistant Guide for Encrypted ERC-20 Protocol

This document provides comprehensive guidance for AI assistants working with the Encrypted ERC-20 (eERC) codebase. Last updated: 2025-11-14

## Project Overview

The Encrypted ERC-20 protocol is a privacy-preserving token implementation developed by AvaCloud that uses zero-knowledge proofs (zk-SNARKs) and partially homomorphic encryption to enable confidential token transfers on EVM-compatible blockchains.

### Key Characteristics

- **Domain**: Blockchain privacy, zero-knowledge cryptography, EVM smart contracts
- **Primary Language**: Solidity 0.8.27 (smart contracts), TypeScript (tests, scripts, SDK)
- **Testing Framework**: Hardhat with Mocha/Chai
- **ZK Framework**: Circom 2.1.9 for circuits, Groth16 proof system
- **Coverage**: ~97% test coverage
- **Security**: Two completed audits (Circom and Gnark circuits)

## Repository Structure

```
TrulyEncryptedERC/
├── contracts/              # Solidity smart contracts
│   ├── EncryptedERC.sol   # Main contract (privacy-preserving ERC20)
│   ├── Registrar.sol      # User registration & public key management
│   ├── EncryptedUserBalances.sol  # Encrypted balance storage
│   ├── auditor/           # Auditor management for compliance
│   ├── errors/            # Custom error definitions
│   ├── interfaces/        # Contract interfaces
│   ├── libraries/         # BabyJubJub elliptic curve operations
│   ├── metadata/          # Encrypted metadata functionality
│   ├── prod/              # Production verifier wrappers (trusted setup)
│   ├── tokens/            # Token tracking and ERC20 utilities
│   ├── types/             # Type definitions and structs
│   └── verifiers/         # Auto-generated ZK proof verifiers
├── circom/                # Zero-knowledge proof circuits
│   ├── registration.circom
│   ├── mint.circom
│   ├── transfer.circom
│   ├── withdraw.circom
│   ├── withdrawIntent.circom
│   ├── burn.circom
│   ├── components.circom  # Shared circuit components
│   └── build/             # Compiled circuits (generated)
├── src/                   # TypeScript SDK utilities
│   ├── jub/               # BabyJubJub encryption/decryption
│   ├── poseidon/          # Poseidon hash implementations
│   ├── constants.ts       # Shared constants
│   └── metadata.ts        # Metadata encryption utilities
├── test/                  # Test files
│   ├── helpers.ts         # Shared test utilities
│   ├── user.ts            # User abstraction for tests
│   ├── EncryptedERC-Standalone.ts  # Tests for standalone mode
│   ├── EncryptedERC-Converter.ts   # Tests for converter mode
│   ├── EncryptedERC-Intent.ts      # Tests for intent system
│   └── EncryptedMetadata.ts        # Metadata tests
├── scripts/               # Deployment and verification scripts
│   ├── deploy-standalone.ts
│   ├── deploy-converter.ts
│   └── verify-*.ts        # Various verification scripts
├── zk/                    # Go implementation (alternative SDK)
│   └── pkg/               # Go packages for ZK operations
├── docs/                  # Documentation
├── audit/                 # Security audit reports
└── hardhat.config.ts      # Hardhat configuration
```

## Core Architecture Concepts

### 1. Two Operation Modes

**Standalone Mode** (`isConverter: false`):
- Creates entirely new private tokens from scratch
- Operations: `privateMint`, `privateBurn`, `transfer`
- Total supply is private
- No underlying ERC20 token

**Converter Mode** (`isConverter: true`):
- Wraps existing ERC20 tokens with privacy
- Operations: `deposit`, `withdraw`, `transfer`
- Deposits convert public ERC20 → private eERC
- Withdrawals convert private eERC → public ERC20

### 2. Key Components

**EncryptedERC** (contracts/EncryptedERC.sol:58):
- Main contract inheriting from TokenTracker, EncryptedUserBalances, AuditorManager, EncryptedMetadata
- Handles all private token operations
- Verifies ZK proofs for each operation
- Manages encrypted balance updates

**Registrar** (contracts/Registrar.sol):
- Manages user registration with ZK proof
- Stores user public keys (BabyJubJub curve points)
- Required before any private operations

**EncryptedUserBalances**:
- Stores encrypted balances as ElGamal ciphertexts (EGCT)
- Structure: `EGCT { Point c1, Point c2 }`
- Balances updated homomorphically without decryption
- Tracks balance history and nonces per user per token

**Zero-Knowledge Circuits** (circom/):
- **Registration**: Proves knowledge of private key for public key
- **Mint**: Proves valid minting with correct encryption
- **Transfer**: Proves sender has sufficient balance, correct encryption for recipient
- **Withdraw**: Proves valid withdrawal amount from encrypted balance
- **WithdrawIntent**: Proves withdrawal intent with hidden amount/destination
- **Burn**: Proves valid burn with correct amount

### 3. Intent-Based Withdrawals (NEW)

Recent implementation (commits 825a229, 1a1d09c, 145c570) introduced privacy-preserving intent system:

- Users submit **intent hash** only (not amount/destination)
- `intentHash = poseidon(amount, destination, tokenId, nonce)` computed in ZK circuit
- Intents can be batched for execution
- Privacy through anonymity sets - observers can't link intent to user
- Two-step system: submit intent → execute intent (after delay)
- Delays: 1 hour (user-only), 24 hours (permissionless)

## Development Workflow

### Prerequisites

- Node.js >= v22.x (.nvmrc specifies version)
- Circom >= 2.1.9
- Git
- npm/npx

### Initial Setup

```bash
git clone https://github.com/ava-labs/EncryptedERC.git
cd EncryptedERC
npm install  # Also compiles contracts and circuits via postinstall
```

### Key Commands

```bash
# Compile contracts
npx hardhat compile

# Compile circuits (generates R1CS, WASM, zkey files)
npx hardhat zkit make --force

# Generate Solidity verifiers from circuits
npx hardhat zkit verifiers

# Run all tests
npx hardhat test

# Run specific test file
npx hardhat test test/EncryptedERC-Standalone.ts

# Generate coverage report
npx hardhat coverage

# Lint Solidity files
npm run lint:sol

# Lint TypeScript files
npm run lint:ts

# Run all lints
npm run lint

# Start local Hardhat node
npx hardhat node

# Deploy standalone mode
npx hardhat run scripts/deploy-standalone.ts --network localhost

# Deploy converter mode
npx hardhat run scripts/deploy-converter.ts --network localhost
```

### CI/CD Pipeline

GitHub Actions workflow (.github/workflows/ci.yml):
1. Checkout code
2. Install dependencies
3. Run coverage (npx hardhat coverage)
4. Run linters

Runs on: pull requests, pushes to main, manual dispatch

## Coding Conventions

### Solidity Style

**Version**: Exactly 0.8.27 (enforced by solhint)

**Formatting** (.prettierrc):
- Tab width: 4 spaces (not tabs)
- Print width: 80 characters
- No bracket spacing
- Double quotes (not single)

**Naming Conventions** (.solhint.json):
- Private variables: leading underscore (e.g., `_privateVar`)
- Immutable variables: NOT treated as constants (no UPPER_CASE unless truly constant)
- Public variables: camelCase
- Functions: camelCase
- Named parameters required for functions with 5+ parameters

**Imports**:
- Group by type: contracts, libraries, types, errors, interfaces
- OpenZeppelin imports use explicit paths
- Relative imports for local contracts

**Comments**:
- NatSpec documentation for all public/external functions
- ASCII art in main contract header (see EncryptedERC.sol:32-38)
- Copyright notice: `// (c) 2025, Ava Labs, Inc. All rights reserved.`
- License: `// SPDX-License-Identifier: Ecosystem`

**Error Handling**:
- Custom errors defined in contracts/errors/Errors.sol
- No error strings in require (use custom errors)
- Import and use: `UserNotRegistered`, `InvalidProof`, `TransferFailed`, etc.

### TypeScript Style

**Tool**: Biome (not ESLint) via `biome.json`

**Key Patterns in Tests** (test/helpers.ts):
- Use `SignerWithAddress` from Hardhat
- Import types from `generated-types/zkit` for circuits
- Import contract types from `typechain-types`
- User abstraction class in `test/user.ts` for managing keys/balances
- Helper functions: `deployVerifiers()`, `deployLibrary()`, `registerUser()`

**Proof Generation Pattern**:
```typescript
const circuit = await zkit.getCircuit("MintCircuit");
const { proof, publicSignals } = await circuit.generateProof(inputs);
const calldata = await circuit.generateCalldata(proof, publicSignals);
```

### File Organization

**New Contract Checklist**:
1. Add copyright and license headers
2. Create in appropriate subdirectory (interfaces/, libraries/, etc.)
3. Create corresponding interface in interfaces/ if needed
4. Update Types.sol if new structs are needed
5. Add custom errors to errors/Errors.sol
6. Create test file in test/ directory
7. Update imports in main contract if needed

**New Circuit Checklist**:
1. Create .circom file in circom/ directory
2. Import shared components from components.circom if needed
3. Run `npx hardhat zkit make --force`
4. Run `npx hardhat zkit verifiers` to generate Solidity verifier
5. Deploy verifier in test helpers
6. Create corresponding proof structs in Types.sol

## Testing Best Practices

### Test Structure

Each test file should:
1. Import necessary types and contracts
2. Deploy all contracts in `before()` hook
3. Register test users before operations
4. Use descriptive `describe()` blocks for grouping
5. Use `it()` blocks for individual test cases
6. Clean up state between tests with `beforeEach()` when needed

### Common Test Patterns

**User Registration**:
```typescript
const user = new User(signer, registrar, encryptedERC);
await user.register(); // Generates proof and registers
```

**Minting**:
```typescript
const { proof, metadata } = await user.mint(amount, tokenId);
await encryptedERC.privateMint(user.address, proof, metadata);
```

**Transfers**:
```typescript
const { proof, metadata } = await sender.transfer(receiver, amount, tokenId);
await encryptedERC.transfer(receiver.address, tokenId, proof, balancePCT, metadata);
```

**Assertions**:
- Use chai matchers: `expect(...).to.equal(...)`, `expect(...).to.be.revertedWithCustomError(...)`
- Verify proof verification: check transaction doesn't revert
- Verify encrypted balance updates: decrypt and check amounts
- Verify events emitted: `expect(tx).to.emit(contract, "EventName")`

### ZK Circuit Testing

Circuits are tested implicitly through contract tests (proof verification).
Standalone circuit testing uses `@solarity/chai-zkit`:

```typescript
const circuit = await zkit.getCircuit("MintCircuit");
const { proof, publicSignals } = await circuit.generateProof(inputs);
expect(await circuit.verifyProof(proof, publicSignals)).to.be.true;
```

## Cryptographic Primitives

### BabyJubJub Curve

- Used for ElGamal encryption
- Base point: `Base8` from `@zk-kit/baby-jubjub`
- Public key: `publicKey = privateKey * Base8`
- Implemented in contracts/libraries/BabyJubJub.sol and src/jub/

### Poseidon Hash

- ZK-friendly hash function
- Used for computing nullifiers, intent hashes
- Library: `maci-crypto` or `poseidon-lite`
- Import: `import { poseidon } from "maci-crypto/build/ts/hashing"`

### ElGamal Encryption (Partially Homomorphic)

**Encryption** (src/jub/jub.ts):
```typescript
function encryptMessage(publicKey: Point, message: bigint): EGCT {
  // c1 = r * Base8
  // c2 = message * Base8 + r * publicKey
  return { c1, c2 };
}
```

**Homomorphic Addition**:
```solidity
// Can add two ciphertexts without decryption
EGCT newBalance = addEGCT(oldBalance, encryptedAmount);
```

**Decryption** (src/jub/jub.ts):
```typescript
function decryptPoint(privateKey: bigint, ciphertext: EGCT): Point {
  // message * Base8 = c2 - privateKey * c1
  return subtractPoints(c2, scalarMult(c1, privateKey));
}
```

### Public Signals

ZK proofs output public signals that are verified on-chain:
- **Registration**: [publicKeyX, publicKeyY, chainId, registrarAddress, msgSender]
- **Mint**: [encrypted new balance (4 coords), nullifier, encrypted auditor balance, ...]
- **Transfer**: [encrypted sender/receiver balances, token info, ...]
- **Withdraw**: [encrypted new balance, withdrawal amount, ...]
- **WithdrawIntent**: [encrypted new balance, intentHash, ...]

## Common Pitfalls & Gotchas

### 1. Circuit Compilation

- Always run `npx hardhat zkit make --force` after circuit changes
- Always run `npx hardhat zkit verifiers` to update Solidity verifiers
- Don't commit large .ptau files (they're auto-downloaded)
- Verifiers go to contracts/verifiers/ and are auto-generated (don't edit manually)

### 2. Proof Verification

- Proofs must use current on-chain state (nonce, balance)
- Public signals order matters - must match circuit output exactly
- Production vs development verifiers: set `isProd` in deployment scripts
- Production verifiers in contracts/prod/ use trusted setup from zkevm

### 3. Balance Management

- Balances stored as ElGamal ciphertexts (two curve points)
- Balance updates are additive (homomorphic property)
- Nonces increment with each operation (prevent replay)
- Balance history tracked by index for auditing

### 4. Intent System

- Intent hash includes: amount, destination, tokenId, nonce
- Intent hash is PRIVATE (computed in ZK circuit)
- Amounts and destinations NOT revealed on-chain during submission
- Execute intent after delay period
- Maximum intent expiry: 30 days

### 5. Gas Optimization

- Verifier contracts are large (1.3-2MB each)
- Use optimizer: `runs: 200` in hardhat.config.ts
- Use `viaIR: true` for better optimization
- Batch operations when possible (intent batching)

### 6. Type Definitions

- Solidity structs in contracts/types/Types.sol
- TypeScript types auto-generated by typechain in typechain-types/
- ZK circuit types in generated-types/zkit/
- Always import from generated types, not manual definitions

## Security Considerations

### Audit Status

Two completed audits:
1. **Circom circuits audit** (March 2025): audit/avacloud-eerc-circom-audit.pdf
2. **Gnark circuits & protocol audit** (March 2025): audit/avacloud-eerc-audit.pdf

### Security Best Practices

**When modifying contracts**:
- Never skip ZK proof verification
- Always check user registration before operations
- Validate all public inputs to circuits
- Use custom errors (cheaper and clearer than strings)
- Follow checks-effects-interactions pattern
- Be careful with balance updates (they're encrypted)

**When adding new circuits**:
- Ensure all constraints are satisfiable
- Validate range proofs for amounts (prevent overflow)
- Include nullifier checks to prevent double-spend
- Add chain ID to prevent cross-chain replay
- Include contract address in public signals

**Privacy considerations**:
- Never log sensitive amounts on-chain
- Use intent hashes instead of amounts for withdrawals
- Batch operations to increase anonymity sets
- Encrypted metadata should not leak information

### Testing for Security

- Test with malicious inputs (wrong proofs, invalid amounts)
- Test replay attack prevention (reusing nullifiers)
- Test unauthorized access (unregistered users)
- Test edge cases (zero amounts, max amounts)
- Verify events don't leak private information

## Working with AI Assistants

### Do's

✅ **Analyze existing patterns** before proposing changes
✅ **Run tests** after any contract or circuit modifications
✅ **Follow existing code structure** (don't reinvent patterns)
✅ **Use helper functions** from test/helpers.ts
✅ **Check recent commits** for context on new features
✅ **Read documentation** in docs/ folder for complex features
✅ **Verify imports** match existing patterns
✅ **Run linters** before considering code complete

### Don'ts

❌ **Don't modify auto-generated files** (verifiers/, typechain-types/, generated-types/)
❌ **Don't change circuit logic** without deep understanding of ZK constraints
❌ **Don't skip proof verification** in contract functions
❌ **Don't log sensitive data** (private keys, plaintexts, amounts)
❌ **Don't use `console.log` in production contracts** (use events)
❌ **Don't modify .ptau files** (they're from trusted setup)
❌ **Don't change Solidity version** without team discussion
❌ **Don't add dependencies** without checking bundle size impact

### Understanding Context

Before making changes:
1. **Read the README.md** for high-level architecture
2. **Check docs/** for feature-specific documentation
3. **Review test files** to understand expected behavior
4. **Look at recent commits** (git log) for ongoing work
5. **Examine similar existing code** for patterns
6. **Check Types.sol** for data structure definitions

### Proposing Changes

When suggesting modifications:
1. **Identify the affected components** (contracts, circuits, tests)
2. **Explain privacy implications** (if any)
3. **Consider gas costs** (especially for verifier changes)
4. **Propose test coverage** for new functionality
5. **Check backwards compatibility** (especially for circuits)
6. **Mention migration needs** (if changing on-chain state)

## Useful References

### External Documentation

- Circom Documentation: https://docs.circom.io/
- Hardhat Documentation: https://hardhat.org/docs
- BabyJubJub Curve: https://github.com/privacy-scaling-explorations/zk-kit/tree/main/packages/baby-jubjub
- ElGamal Encryption: https://en.wikipedia.org/wiki/ElGamal_encryption
- Poseidon Hash: https://www.poseidon-hash.info/
- AvaCloud Documentation: https://docs.avacloud.io/encrypted-erc

### Internal Files to Reference

- Architecture: README.md:39-246
- Intent System: docs/INTENT_BATCHING_SYSTEM.md
- Deployment Guide: README.md:129-202
- Gas Costs: README.md:262-316
- Main Contract: contracts/EncryptedERC.sol
- Type Definitions: contracts/types/Types.sol
- Test Helpers: test/helpers.ts
- Constants: scripts/constants.ts

## Quick Reference: File Purposes

| File/Directory | Purpose | Can Modify? |
|----------------|---------|-------------|
| contracts/*.sol | Smart contract source | ✅ Yes (with tests) |
| contracts/verifiers/ | Auto-generated ZK verifiers | ❌ No (regenerate via zkit) |
| circom/*.circom | ZK circuit definitions | ✅ Yes (expert only) |
| test/*.ts | Test files | ✅ Yes |
| scripts/*.ts | Deployment scripts | ✅ Yes |
| src/ | TypeScript SDK utilities | ✅ Yes |
| typechain-types/ | Auto-generated TS types | ❌ No |
| generated-types/zkit/ | Auto-generated circuit types | ❌ No |
| hardhat.config.ts | Hardhat configuration | ✅ Yes (carefully) |
| package.json | Dependencies and scripts | ✅ Yes (check impacts) |

## Environment Variables

From .env.example:
- `RPC_URL`: Ethereum RPC endpoint (default: Avalanche C-Chain)
- `PRIVATE_KEY`: Deployer private key for testnet/mainnet
- `FORKING`: Enable Hardhat forking mode
- `REPORT_GAS`: Enable gas reporting
- `COINMARKETCAP_API_KEY`: For USD gas cost estimation

## Network Configuration

From hardhat.config.ts:26-39:
- **hardhat**: Local development network with optional forking
- **fuji**: Avalanche Fuji testnet (chainId: 43113)

For production: Add mainnet configuration as needed

## Recent Changes (Last 5 Commits)

1. `825a229`: Documentation updates, roadmap, and tests
2. `1a1d09c`: Intent system no longer includes amounts in calldata
3. `70bf662`: Bug fixes ("oof")
4. `145c570`: Private amounts in intent withdrawals
5. `95f7cf5`: Intent withdrawals working without regressions

**Key Insight**: Recent work focused on privacy-preserving intent system where amounts/destinations are hidden in ZK proofs.

## Debugging Tips

### Contract Debugging

- Use `console.log` from Hardhat (import from "hardhat/console.sol")
- Enable verbose errors: check custom error parameters
- Verify proof manually if verification fails
- Check nonce values if replay errors occur
- Inspect emitted events for state changes

### Circuit Debugging

- Use `console.log()` in Circom (outputs during witness generation)
- Check constraint count: `npx hardhat zkit info <circuit-name>`
- Verify inputs satisfy constraints before generating proof
- Check public signals match expected values
- Use smaller test cases to isolate issues

### Test Debugging

- Run single test: `npx hardhat test --grep "test name pattern"`
- Add `.only` to specific test: `it.only("test", ...)`
- Check transaction logs: `await tx.wait()` then inspect events
- Decrypt balances manually to verify correctness
- Add console.logs in User class methods (test/user.ts)

---

**Last Updated**: 2025-11-14
**Codebase Version**: As of commit 825a229 (docs, roadmap and tests)
**Maintainer**: AvaCloud / Ava Labs
**Repository**: https://github.com/ava-labs/EncryptedERC
