// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IVerdictSigVerifier} from "./IVerdictSigVerifier.sol";

/// @dev Minimal local copy of Safe's Enum.Operation (0=Call, 1=DelegateCall) — kept as a plain
///      enum rather than importing safe-smart-account so this integration has zero contract
///      dependencies beyond the verdict-sig verifier, same posture as integrations/erc7579/.
enum Operation {
    Call,
    DelegateCall
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// @dev Safe's owner-signed transaction path (Safe.execTransaction -> GuardManager.checkTransaction).
interface ITransactionGuard is IERC165 {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 hash, bool success) external;
}

/// @dev Safe's module-triggered transaction path (ModuleManager.execTransactionFromModule ->
///      checkModuleTransaction). This is the path Snapshot's oSnap (Zodiac module) and every
///      other Safe module — including any future DAO-execution module — actually executes
///      through. A regular ITransactionGuard alone does NOT see these; a Safe must register a
///      separate module guard (setModuleGuard) for module-triggered actions to be gated too.
interface IModuleGuard is IERC165 {
    function checkModuleTransaction(address to, uint256 value, bytes memory data, Operation operation, address module)
        external
        returns (bytes32 moduleTxHash);

    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}

/// @title InvinoveritasSafeGuard
/// @notice A Safe{Wallet} Transaction Guard AND Module Guard that turns an *independent,
///         recomputable* invinoveritas `/review` verdict into a fail-closed pre-execution gate —
///         for both owner-signed Safe transactions and module-triggered ones (Snapshot's oSnap,
///         any Zodiac module, any future DAO-execution module). One contract, registered in both
///         guard slots, covers the dominant Safe-based DAO treasury execution surface.
///
/// Same verdict-commitment construction as integrations/erc7579/src/InvinoveritasPolicyHook.sol
/// (the settlement-side pattern proven there): recompute the action digest from the ACTUAL
/// execution about to run, require a recorded, unexpired, unconsumed, independently-signed
/// approve-verdict binding to that exact digest, fail-closed otherwise. See that contract's
/// docstring for the full "what makes it evidence and not an attestation" reasoning — identical
/// here, different venue.
///
/// ## Explicitly NOT covered
/// On-chain Governor + TimelockController stacks (the OpenZeppelin Governor pattern Tally and
/// most non-Safe on-chain DAOs use) do not route execution through a Safe at all — there is no
/// Guard slot to hook into. Gating that path needs a different integration (a Timelock-compatible
/// executor/extension), not this contract. Scoped separately, not built here.
///
/// ## Delegatecall — deliberately NOT banned (unlike the ERC-7579 hook)
/// integrations/erc7579/InvinoveritasPolicyHook refuses to admit any delegatecall outright. This
/// contract does not, because Safe's MultiSend batching — delegatecalling the canonical MultiSend
/// library to bundle several calls into one transaction — is standard, legitimate DAO practice,
/// not a red flag. Banning it here would make the guard impractical for a large share of real Safe
/// usage. A genuinely risky delegatecall (to an unverified or malicious target) is exactly the
/// kind of thing the /review verdict itself is supposed to catch during reasoning, not something
/// this contract should hard-code a blanket ban on.
contract InvinoveritasSafeGuard is ITransactionGuard, IModuleGuard {
    // ---- verdict codes (mirror the off-chain Verdict enum; only "approve" classes unlock) ----
    uint8 public constant VERDICT_APPROVE = 1;
    uint8 public constant VERDICT_APPROVE_WITH_CONCERNS = 2;
    // 3 = reject, 0 = review_unavailable — never unlock execution.

    /// @dev domain separator so a verdict commitment can't be replayed as some other signed message.
    bytes32 public constant VERDICT_DOMAIN = keccak256("invinoveritas.safe_verdict.v1");

    struct Approval {
        bool exists;
        bool consumed; // single-use: a recorded verdict admits exactly one execution
        uint64 expiry;
        bytes32 verifier; // x-only secp256k1 pubkey that signed it
    }

    IVerdictSigVerifier public immutable sigVerifier;

    /// @dev per-safe independence allowlist: safe => verifier x-only pubkey => allowed.
    mapping(address => mapping(bytes32 => bool)) public independentVerifier;
    /// @dev per-safe recorded approvals keyed by the recomputed action digest.
    mapping(address => mapping(bytes32 => Approval)) public approvalOf;

    event VerifierSet(address indexed safe, bytes32 indexed verifierPubkey, bool allowed);
    event VerdictRecorded(
        address indexed safe, bytes32 indexed actionDigest, uint8 verdictCode, bytes32 verifierPubkey, uint64 expiry
    );
    event ActionAdmitted(address indexed safe, bytes32 indexed actionDigest, bytes32 verifierPubkey, bool viaModule);

    constructor(IVerdictSigVerifier _sigVerifier) {
        require(address(_sigVerifier) != address(0), "sigVerifier=0");
        sigVerifier = _sigVerifier;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IModuleGuard).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice A Safe adjusts its OWN independence allowlist (msg.sender must be the Safe itself,
    ///         e.g. via a self-call in the Safe's own setup/execTransaction — same self-authorized
    ///         pattern Safe's own GuardManager.setGuard uses).
    function setVerifier(bytes32 verifierPubkey, bool allowed) external {
        independentVerifier[msg.sender][verifierPubkey] = allowed;
        emit VerifierSet(msg.sender, verifierPubkey, allowed);
    }

    // ---------------------------------------------------------------- verdict recording

    /// @notice Record a signed, independent approve-verdict for `safe` that binds to `actionDigest`.
    ///         Callable by anyone (the signature is the authority, not msg.sender). Single-use.
    function recordVerdict(
        address safe,
        bytes32 actionDigest,
        uint8 verdictCode,
        bytes32 verifierPubkey,
        uint64 expiry,
        bytes calldata signature
    ) external {
        require(independentVerifier[safe][verifierPubkey], "verifier not in independence allowlist");
        require(verdictCode == VERDICT_APPROVE || verdictCode == VERDICT_APPROVE_WITH_CONCERNS, "not an approve verdict");
        require(block.timestamp <= expiry, "verdict already expired");
        bytes32 commitment = verdictCommitment(safe, actionDigest, verdictCode, verifierPubkey, expiry);
        require(sigVerifier.verify(verifierPubkey, commitment, signature), "verdict signature invalid");
        approvalOf[safe][actionDigest] = Approval(true, false, expiry, verifierPubkey);
        emit VerdictRecorded(safe, actionDigest, verdictCode, verifierPubkey, expiry);
    }

    /// @notice The exact 32-byte preimage an independent verifier must sign for an on-chain verdict.
    function verdictCommitment(
        address safe,
        bytes32 actionDigest,
        uint8 verdictCode,
        bytes32 verifierPubkey,
        uint64 expiry
    ) public view returns (bytes32) {
        return sha256(
            abi.encode(VERDICT_DOMAIN, block.chainid, address(this), safe, actionDigest, verdictCode, verifierPubkey, expiry)
        );
    }

    /// @notice The on-chain action canonicalization: recompute this from the transaction you intend
    ///         to run, then obtain a /review verdict whose attestation binds to it.
    function computeActionDigest(address safe, address to, uint256 value, bytes calldata data, Operation operation)
        public
        view
        returns (bytes32)
    {
        return sha256(abi.encode(block.chainid, safe, to, value, data, operation));
    }

    function _admit(address safe, address to, uint256 value, bytes memory data, Operation operation, bool viaModule)
        private
        returns (bytes32 actionDigest)
    {
        actionDigest = sha256(abi.encode(block.chainid, safe, to, value, data, operation));
        Approval storage a = approvalOf[safe][actionDigest];
        require(a.exists, "no independent approve verdict for this exact transaction"); // fail-closed
        require(!a.consumed, "verdict already consumed");
        require(block.timestamp <= a.expiry, "verdict expired");
        a.consumed = true;
        emit ActionAdmitted(safe, actionDigest, a.verifier, viaModule);
    }

    // ---------------------------------------------------------------- ITransactionGuard (owner-signed path)

    /// @inheritdoc ITransactionGuard
    /// @dev msg.sender is the Safe. Reverts (fail-closed) unless a recorded, unexpired, unconsumed,
    ///      independent approve-verdict binds to the recomputed digest of THIS transaction. Gas/
    ///      refund parameters (safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures,
    ///      msgSender) are intentionally excluded from the digest — they're payment bookkeeping,
    ///      not part of what action is being taken.
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256, /*safeTxGas*/
        uint256, /*baseGas*/
        uint256, /*gasPrice*/
        address, /*gasToken*/
        address payable, /*refundReceiver*/
        bytes memory, /*signatures*/
        address /*msgSender*/
    ) external override {
        _admit(msg.sender, to, value, data, operation, false);
    }

    /// @inheritdoc ITransactionGuard
    function checkAfterExecution(bytes32, bool) external override {}

    // ---------------------------------------------------------------- IModuleGuard (module-triggered path)

    /// @inheritdoc IModuleGuard
    /// @dev msg.sender is the Safe. Same fail-closed admission as checkTransaction, over the same
    ///      digest shape — a verdict obtained for a transaction is venue-agnostic; whether it
    ///      executes via an owner's signatures or via a module (oSnap, any Zodiac module) doesn't
    ///      change what the verdict is about.
    function checkModuleTransaction(address to, uint256 value, bytes memory data, Operation operation, address /*module*/)
        external
        override
        returns (bytes32 moduleTxHash)
    {
        moduleTxHash = _admit(msg.sender, to, value, data, operation, true);
    }

    /// @inheritdoc IModuleGuard
    function checkAfterModuleExecution(bytes32, bool) external override {}
}
