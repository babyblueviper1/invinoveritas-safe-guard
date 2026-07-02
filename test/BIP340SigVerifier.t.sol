// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {BIP340SigVerifier} from "../src/BIP340SigVerifier.sol";

/// @notice Exercises BIP340SigVerifier against a REAL BIP-340 signature (not a mock) — the exact
///         vector from TMerlini/hack-ens-recovery contracts/test/BIP340.t.sol, produced off-chain
///         by noble-curves (the same library the invinoveritas SDK signs with). A green
///         test_RealSignatureVerifies proves this adapter's signature-unpacking (rx‖s -> BIP340.verify)
///         agrees with the canonical signer, end to end — genuine cryptographic correctness, not an
///         assertion.
contract BIP340SigVerifierTest is Test {
    BIP340SigVerifier verifier;

    // Vector 1 (real): sk = sha256("bip340-verifier-test-key-1"); m = sha256("the message being signed ...")
    bytes32 constant PX = 0xc2dfd401c46c8d273b9b8deccf29eb8a56593f25421b91649904d56d28a784ad;
    bytes32 constant RX = 0xb2d7c6d2d094fd749657dabfefed129c764a9b495b620f50438231ba9be904a6;
    bytes32 constant S = 0x7b3d8e2f90b1ba58ff7066d5f43346bb9cb0a09a27e10ad466fce1ad9469223b;
    bytes32 constant M = 0xb6d2d081d098f3026715b07380b1571acda72d8c7fe18c002f1a447a1d88d307;

    function setUp() public {
        verifier = new BIP340SigVerifier();
    }

    function _sig() internal pure returns (bytes memory) {
        return abi.encodePacked(RX, S); // standard 64-byte BIP-340 encoding: rx || s
    }

    function test_RealSignatureVerifies() public view {
        assertTrue(verifier.verify(PX, M, _sig()), "real BIP-340 signature must verify");
    }

    function test_WrongMessageRejected() public view {
        assertFalse(verifier.verify(PX, bytes32(uint256(M) ^ 1), _sig()));
    }

    function test_WrongPubkeyRejected() public view {
        assertFalse(verifier.verify(bytes32(uint256(PX) ^ 1), M, _sig()));
    }

    function test_TamperedSRejected() public view {
        bytes memory tampered = abi.encodePacked(RX, bytes32(uint256(S) ^ 1));
        assertFalse(verifier.verify(PX, M, tampered));
    }

    function test_TamperedRxRejected() public view {
        bytes memory tampered = abi.encodePacked(bytes32(uint256(RX) ^ 1), S);
        assertFalse(verifier.verify(PX, M, tampered));
    }

    function test_WrongLengthSignatureRejected() public view {
        assertFalse(verifier.verify(PX, M, abi.encodePacked(RX))); // 32 bytes, not 64
        assertFalse(verifier.verify(PX, M, abi.encodePacked(RX, S, S))); // 96 bytes, not 64
    }

    function test_EmptySignatureRejected() public view {
        assertFalse(verifier.verify(PX, M, ""));
    }
}
