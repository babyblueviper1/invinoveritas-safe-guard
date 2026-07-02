// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {
    InvinoveritasSafeGuard,
    Operation,
    ITransactionGuard,
    IModuleGuard,
    IERC165
} from "../src/InvinoveritasSafeGuard.sol";
import {MockVerdictSigVerifier} from "./MockVerdictSigVerifier.sol";

/// @notice Exercises the guard's gate logic (both ITransactionGuard and IModuleGuard entry points)
///         against the mock signature verifier. Run: `forge test`.
contract InvinoveritasSafeGuardTest is Test {
    InvinoveritasSafeGuard guard;
    MockVerdictSigVerifier sig;

    address safe = address(0x5AFE);
    address module = address(0x0DDBA11);
    bytes32 verifier = bytes32(uint256(0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7));
    bytes32 strangerKey = bytes32(uint256(0xBEEF));
    bytes mockSig = hex"01";

    address to = address(0xCAFE);
    uint256 value = 1 ether;
    bytes data = hex"a9059cbb"; // e.g. erc20 transfer selector
    Operation operation = Operation.Call;

    function setUp() public {
        sig = new MockVerdictSigVerifier();
        guard = new InvinoveritasSafeGuard(sig);
        vm.prank(safe);
        guard.setVerifier(verifier, true);
    }

    function _digest() internal view returns (bytes32) {
        return guard.computeActionDigest(safe, to, value, data, operation);
    }

    function _recordApprove(uint64 expiry) internal {
        bytes32 d = _digest();
        bytes32 commitment = guard.verdictCommitment(safe, d, guard.VERDICT_APPROVE(), verifier, expiry);
        sig.setValid(verifier, commitment, mockSig, true);
        guard.recordVerdict(safe, d, guard.VERDICT_APPROVE(), verifier, expiry, mockSig);
    }

    function test_SupportsBothGuardInterfaces() public view {
        assertTrue(guard.supportsInterface(type(ITransactionGuard).interfaceId));
        assertTrue(guard.supportsInterface(type(IModuleGuard).interfaceId));
        assertTrue(guard.supportsInterface(type(IERC165).interfaceId));
        assertFalse(guard.supportsInterface(bytes4(0xdeadbeef)));
    }

    // ---------------------------------------------------------------- owner-signed path (checkTransaction)

    function test_OwnerPath_ApproveUnlocksExactTransaction() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(safe);
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
        (, bool consumed,,) = guard.approvalOf(safe, _digest());
        assertTrue(consumed);
    }

    function test_OwnerPath_RevertWhen_NoVerdict() public {
        vm.prank(safe);
        vm.expectRevert(bytes("no independent approve verdict for this exact transaction"));
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
    }

    function test_OwnerPath_RevertWhen_Replay() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(safe);
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
        vm.prank(safe);
        vm.expectRevert(bytes("verdict already consumed"));
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
    }

    function test_OwnerPath_GasParamsExcludedFromDigest() public {
        // A verdict recorded under one set of gas/refund params still admits the transaction when
        // those params differ at execution time — they're payment bookkeeping, not the action.
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(safe);
        guard.checkTransaction(
            to, value, data, operation, 999_999, 12345, 7, address(0xF00D), payable(address(0xBEEF)), hex"aabb", address(this)
        ); // does not revert despite completely different gas/refund params
    }

    // ---------------------------------------------------------------- module-triggered path (checkModuleTransaction)

    function test_ModulePath_ApproveUnlocksExactTransaction() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(safe);
        bytes32 h = guard.checkModuleTransaction(to, value, data, operation, module);
        assertEq(h, _digest());
        (, bool consumed,,) = guard.approvalOf(safe, _digest());
        assertTrue(consumed);
    }

    function test_ModulePath_RevertWhen_NoVerdict() public {
        vm.prank(safe);
        vm.expectRevert(bytes("no independent approve verdict for this exact transaction"));
        guard.checkModuleTransaction(to, value, data, operation, module);
    }

    function test_ModulePath_SameVerdictNotReusableAfterOwnerPathConsumedIt() public {
        // A single recorded verdict is single-use REGARDLESS of which path consumes it first —
        // the verdict is about the action, not about which execution mechanism runs it.
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(safe);
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
        vm.prank(safe);
        vm.expectRevert(bytes("verdict already consumed"));
        guard.checkModuleTransaction(to, value, data, operation, module);
    }

    // ---------------------------------------------------------------- shared verdict-recording logic

    function test_RevertWhen_RejectVerdict() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 commitment = guard.verdictCommitment(safe, d, 3, verifier, expiry); // 3 = reject
        sig.setValid(verifier, commitment, mockSig, true);
        vm.expectRevert(bytes("not an approve verdict"));
        guard.recordVerdict(safe, d, 3, verifier, expiry, mockSig);
    }

    function test_RevertWhen_VerifierNotAllowlisted() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint8 approve = guard.VERDICT_APPROVE(); // evaluate BEFORE expectRevert — an argument
            // expression that itself makes an external call (a view getter, here) counts as
            // the "next call" Foundry intercepts, so it must not be inlined into the call below.
        vm.expectRevert(bytes("verifier not in independence allowlist"));
        guard.recordVerdict(safe, d, approve, strangerKey, expiry, mockSig);
    }

    function test_RevertWhen_BadSignature() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint8 approve = guard.VERDICT_APPROVE(); // see comment above
        vm.expectRevert(bytes("verdict signature invalid"));
        guard.recordVerdict(safe, d, approve, verifier, expiry, mockSig);
    }

    function test_RevertWhen_DigestMismatch_BindingHolds() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        bytes memory differentData = hex"deadbeef";
        vm.prank(safe);
        vm.expectRevert(bytes("no independent approve verdict for this exact transaction"));
        guard.checkTransaction(
            to, value, differentData, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this)
        );
    }

    function test_RevertWhen_Expired() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);
        _recordApprove(expiry);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(safe);
        vm.expectRevert(bytes("verdict expired"));
        guard.checkTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), "", address(this));
    }

    function test_DelegatecallNotBlanketBanned() public {
        // Unlike the ERC-7579 hook, delegatecall is not refused outright (MultiSend batching is
        // legitimate Safe practice) — a verdict for a delegatecall action admits it like any other,
        // as long as the verdict itself was actually issued for that exact action.
        Operation delegateOp = Operation.DelegateCall;
        bytes32 d = guard.computeActionDigest(safe, to, value, data, delegateOp);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 commitment = guard.verdictCommitment(safe, d, guard.VERDICT_APPROVE(), verifier, expiry);
        sig.setValid(verifier, commitment, mockSig, true);
        guard.recordVerdict(safe, d, guard.VERDICT_APPROVE(), verifier, expiry, mockSig);
        vm.prank(safe);
        guard.checkTransaction(to, value, data, delegateOp, 0, 0, 0, address(0), payable(address(0)), "", address(this));
    }
}
