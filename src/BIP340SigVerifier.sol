// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IVerdictSigVerifier} from "./IVerdictSigVerifier.sol";
import {BIP340} from "./BIP340.sol";

/// @title BIP340SigVerifier
/// @notice A real, on-chain, no-oracle IVerdictSigVerifier implementation — not the mock. Unpacks a
///         standard 64-byte BIP-340 signature (rx‖s) and delegates to BIP340.verify. This is the
///         concrete verifier InvinoveritasSafeGuard is meant to be deployed with; the constructor's
///         `IVerdictSigVerifier` parameter exists precisely so this can be swapped for any other
///         audited implementation without touching the guard itself.
///
/// Unlike TMerlini/hack-ens-recovery's BIP340Verifier (which pins a single issuer key and parses a
/// full NIP-01 receipt preimage for a specific schema), this is generic: any pubkey, any 32-byte
/// digest — the guard's own independent-verifier allowlist is what constrains WHICH pubkeys count,
/// not this contract. Same underlying crypto (BIP340.sol, verbatim + credited), different shape to
/// match IVerdictSigVerifier instead of IReceiptVerifier.
contract BIP340SigVerifier is IVerdictSigVerifier {
    /// @inheritdoc IVerdictSigVerifier
    /// @dev `signature` must be exactly 64 bytes: rx (32) || s (32), the standard BIP-340 encoding.
    ///      Never reverts on malformed input — returns false (matches BIP340.verify's own posture).
    function verify(bytes32 pubkey, bytes32 digest, bytes calldata signature) external view override returns (bool) {
        if (signature.length != 64) return false;
        bytes32 rx = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        return BIP340.verify(pubkey, rx, s, digest);
    }
}
