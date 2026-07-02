# invinoveritas Safe{Wallet} Guard (reference)

**A Safe{Wallet} Transaction Guard *and* Module Guard, in one contract, that turns an independent, recomputable [`/review`](https://api.babyblueviper.com) verdict into an on-chain, fail-closed pre-execution gate for a DAO treasury Safe.**

Settlement-side sibling of [`../erc7579`](../erc7579) (the same pattern for ERC-7579 modular smart accounts) — same verdict-commitment construction, different venue. A DAO treasury proposing a transfer/swap/contract call gets exactly the same property an ERC-7579 account gets: it cannot execute a covered transaction unless an independent approve-verdict binding to that *exact* transaction has been recorded and signature-verified.

## Why one contract implements two guard interfaces

Safe has two separate guard slots, checked on two separate execution paths:

- **`ITransactionGuard`** (`setGuard`) — checked on owner-signed transactions, the normal multisig-approval flow.
- **`IModuleGuard`** (`setModuleGuard`) — checked on module-triggered transactions. This is the path **Snapshot's oSnap** (a Zodiac module that executes a passed off-chain vote directly on a Safe) and any other Zodiac-style module actually runs through. A regular transaction guard alone does **not** see these — a Safe has to register a module guard separately for module-executed actions to be gated too.

`InvinoveritasSafeGuard` implements both interfaces over the same underlying verdict logic, so registering it in both slots covers the dominant Safe-based DAO treasury execution surface — direct multisig transactions *and* governance-triggered ones — with one deployment.

## Explicitly not covered

On-chain **Governor + TimelockController** stacks (the OpenZeppelin Governor pattern Tally and most non-Safe on-chain DAOs run) don't route execution through a Safe at all — there's no guard slot to hook into. Gating that path needs a different integration (a Timelock-compatible executor/extension), which is a genuinely different contract shape and is not built here. If a Timelock-based DAO ever wants this, that's a separate scoping exercise.

## The three properties that make it evidence, not an attestation

Identical to the ERC-7579 hook — see [`../erc7579/README.md`](../erc7579/README.md#the-three-properties-that-make-it-evidence-not-an-attestation) for the full reasoning. In short: recompute the digest from the *actual* transaction (never trust a caller-supplied value), require independence (a self-signed verdict cannot unlock execution), fail-closed (no matching verdict ⇒ revert).

## Delegatecall — deliberately not banned here

The ERC-7579 hook refuses delegatecall outright. This contract doesn't, because Safe's **MultiSend** batching — delegatecalling the canonical MultiSend library to bundle several calls into one transaction — is standard, legitimate DAO practice, not a red flag. A genuinely risky delegatecall (to an unverified or malicious target) is exactly the kind of thing the `/review` verdict's own reasoning is supposed to catch, not something this contract should hard-code a blanket ban on.

## Flow

```
1. Build the Safe transaction (to, value, data, operation) you intend to run.
2. digest = guard.computeActionDigest(safe, to, value, data, operation)     // recompute it
3. Get an independent verdict bound to `digest` from /review, expressed as a
   BIP-340 signature over guard.verdictCommitment(safe, digest, code, key, expiry).
4. anyone calls guard.recordVerdict(safe, digest, code, key, expiry, sig)   // sig is the authority
5. The Safe owners sign + execute (or a module like oSnap executes). The
   registered guard(s) recompute the digest from the real transaction and
   admit it exactly once — or revert, fail-closed.
```

## Setup on a Safe

```
safe.setGuard(guardAddress)         // gates owner-signed execTransaction
safe.setModuleGuard(guardAddress)   // gates module-triggered execTransactionFromModule (oSnap, etc.)
guard.setVerifier(verifierPubkey, true)   // called BY the Safe (self-authorized), allowlists an independent verifier
```

## Files

| File | What |
|---|---|
| [`src/InvinoveritasSafeGuard.sol`](src/InvinoveritasSafeGuard.sol) | the guard (implements both `ITransactionGuard` and `IModuleGuard`) |
| [`src/IVerdictSigVerifier.sol`](src/IVerdictSigVerifier.sol) | pluggable signature-verifier interface (wire a BIP-340 verifier) |
| [`src/BIP340.sol`](src/BIP340.sol) | on-chain BIP-340 schnorr verification (ecrecover trick), credited copy from [TMerlini/hack-ens-recovery](https://github.com/TMerlini/hack-ens-recovery) (Apache-2.0) |
| [`src/BIP340SigVerifier.sol`](src/BIP340SigVerifier.sol) | the real `IVerdictSigVerifier` implementation deployed below — unpacks a 64-byte signature and delegates to `BIP340.sol` |
| [`test/InvinoveritasSafeGuard.t.sol`](test/InvinoveritasSafeGuard.t.sol) | Foundry tests: both guard paths, cross-path single-use consumption, fail-closed, expiry, replay, delegatecall NOT refused |
| [`test/MockVerdictSigVerifier.sol`](test/MockVerdictSigVerifier.sol) | test double for the verifier (used by the guard's own tests) |
| [`test/BIP340SigVerifier.t.sol`](test/BIP340SigVerifier.t.sol) | tests `BIP340SigVerifier` against a REAL noble-curves-signed BIP-340 vector, not a mock |

## Build & test

```bash
forge install foundry-rs/forge-std
forge build
forge test
```

21/21 tests genuinely pass (actually run with `forge test`, not just compile-checked) — 14 for the guard, 7 for the real BIP-340 signature adapter.

## Deployed — Sepolia (testnet, 2026-07-02)

| contract | address |
|---|---|
| `BIP340SigVerifier` | [`0x0c213a22a3A1FA051B32f89DaEa2aa23c65f4b96`](https://sepolia.etherscan.io/address/0x0c213a22a3A1FA051B32f89DaEa2aa23c65f4b96) |
| `InvinoveritasSafeGuard` | [`0x22A34DD7339D1aFE76e741e845946d39560bE4c2`](https://sepolia.etherscan.io/address/0x22A34DD7339D1aFE76e741e845946d39560bE4c2) |

Wiring confirmed on-chain: `InvinoveritasSafeGuard.sigVerifier()` reads back `0x0c21…4b96` — the exact `BIP340SigVerifier` deployed above.

Deployed bytecode independently checked against the locally compiled source: byte-for-byte identical except the one 32-byte slot where Solidity bakes in the `sigVerifier` immutable (zero-filled in an abstract, undeployed compile; the real address on-chain) — i.e. what's live matches this repo exactly, verified by recomputation rather than trusting a block explorer's verification badge. Source not yet submitted to Etherscan's own verifier (no API key provisioned for this) — recompute-verification above is the actual guarantee; Etherscan verification would only add UI convenience.

**Testnet only — no real Safe has this wired in yet, and it should not be, before an independent audit.** Deployed for public inspection and to prove the contracts are real and correctly linked, not as an invitation to use in production.

## Scope

Reference / educational. Not audited — wire an audited BIP-340 verifier and review before any mainnet use. Composes with, and does not replace, a Safe's own owner threshold and module permissions; it adds the independent-verdict precondition they can't express.

## Related

- [`../erc7579`](../erc7579) — the same pattern for ERC-7579 modular smart accounts
- [`invinoveritas-governance-gate-core`](../governance-gate-core) — the framework-agnostic verdict primitive
- [preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance) — the conformance suite: independent verdict + external Bitcoin-anchored ordering, recomputable from public bytes
