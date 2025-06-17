// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibString} from "solady/utils/LibString.sol";

import {UserOpMultiSigVerifier} from "../../src/verifier/UserOpMultiSigVerifier.sol";

contract UserOpMultiSigVerifierTest is Test {
    UserOpMultiSigVerifier public verifier;

    struct Signer {
        address addr;
        uint256 pk;
    }

    function setUp() public {
        verifier = new UserOpMultiSigVerifier(address(this));
    }

    function testFuzz_validateData(bool withUserOp, uint8 threshold, uint8 offset, uint8 size) public {
        _assume(threshold, offset, size);
        Signer[] memory signers = _createSigners(size);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = _createData(message, threshold, offset, signers);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = data;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        bytes memory config = _createConfig(threshold, signers);

        uint256 validationData = verifier.validateData(message, data, config);
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function testFuzz_validateDataValidationFailed(bool withUserOp, uint8 threshold, uint8 offset, uint8 size) public {
        _assume(threshold, offset, size);
        Signer[] memory signers = _createSigners(size);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = _createData(message, threshold - 1, offset, signers);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = data;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        bytes memory config = _createConfig(threshold, signers);

        uint256 validationData = verifier.validateData(message, data, config);
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testFuzz_validateDataInvalidCaller(address keystore) public {
        vm.assume(keystore != address(this));
        vm.prank(keystore);
        vm.expectRevert("verifier: not from Keystore");
        verifier.validateData(0, "", "");
    }

    function testFuzz_validateDataInvalidData(bytes calldata data) public {
        vm.expectRevert();
        verifier.validateData(0, data, "");
    }

    // ================================================================
    // Helper functions
    // ================================================================

    function _assume(uint8 threshold, uint8 offset, uint8 size) internal pure {
        vm.assume(threshold > 0 && size > 0 && threshold <= size);
        vm.assume(uint16(threshold) + uint16(offset) <= size);
    }

    function _createSigners(uint8 size) internal returns (Signer[] memory) {
        Signer[] memory signers = new Signer[](size);
        for (uint8 i = 0; i < size; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(LibString.toString(i));
            signers[i] = Signer({addr: addr, pk: pk});
        }
        return signers;
    }

    function _createConfig(uint8 threshold, Signer[] memory signers) internal pure returns (bytes memory) {
        address[] memory signersAddr = new address[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            signersAddr[i] = signers[i].addr;
        }

        return abi.encode(threshold, signersAddr);
    }

    function _createData(bytes32 message, uint8 threshold, uint8 offset, Signer[] memory signers)
        internal
        pure
        returns (bytes memory)
    {
        UserOpMultiSigVerifier.SignerData[] memory sd = new UserOpMultiSigVerifier.SignerData[](threshold);
        for (uint8 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signers[i + offset].pk, message);
            sd[i] = UserOpMultiSigVerifier.SignerData({index: i + offset, signature: abi.encodePacked(r, s, v)});
        }

        return abi.encode(sd);
    }
}
