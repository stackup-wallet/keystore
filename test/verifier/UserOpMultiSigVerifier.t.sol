// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibString} from "solady/utils/LibString.sol";

import {OnlyKeystore} from "../../src/lib/OnlyKeystore.sol";
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

    function testFuzz_validateDataZeroThreshold(bool withUserOp, uint8 offset, uint8 size) public {
        uint8 threshold = 0;
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

        vm.expectRevert(UserOpMultiSigVerifier.ZeroThresholdNotAllowed.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataMinOwners(bool withUserOp, uint8 threshold, uint8 size) public {
        vm.assume(threshold > 0 && size < threshold);
        Signer[] memory signers = _createSigners(size);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = _createData(message, size, 0, signers);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = data;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        bytes memory config = _createConfig(threshold, signers);

        vm.expectRevert(UserOpMultiSigVerifier.InvalidNumberOfOwners.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataMaxOwners(bool withUserOp, uint8 threshold, uint8 offset, uint8 excess) public {
        uint16 size = _getSizeAndAssumeMaxOwnerLimitExceeded(threshold, offset, excess);
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

        vm.expectRevert(UserOpMultiSigVerifier.InvalidNumberOfOwners.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataIncorrectlySortedOwners(bool withUserOp, uint8 threshold, uint8 offset, uint8 size)
        public
    {
        vm.assume(size > 1);
        _assume(threshold, offset, size);
        Signer[] memory signers = _createSignersReverse(size);

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

        vm.expectRevert(UserOpMultiSigVerifier.OwnersUnsortedOrHasDuplicates.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataDuplicateOwners(bool withUserOp, uint8 threshold, uint8 offset, uint8 size) public {
        vm.assume(threshold > 1);
        _assume(threshold, offset, size);

        (address addr, uint256 pk) = makeAddrAndKey("duplicate");
        Signer[] memory signers = new Signer[](size);
        for (uint8 i = 0; i < size; i++) {
            signers[i] = Signer({addr: addr, pk: pk});
        }

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

        vm.expectRevert(UserOpMultiSigVerifier.OwnersUnsortedOrHasDuplicates.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataDuplicateSignatures(
        bool withUserOp,
        uint8 threshold,
        uint8 offset,
        uint8 size,
        uint8 dup
    ) public {
        // Note: set threshold > 1 to show we can't recycle the same signature
        // multiple times.
        vm.assume(threshold > 1 && dup > 1 && dup <= threshold);
        _assume(threshold, offset, size);
        Signer[] memory signers = _createSigners(size);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = _createData(message, threshold, offset, signers);
        UserOpMultiSigVerifier.SignerData[] memory sd = abi.decode(data, (UserOpMultiSigVerifier.SignerData[]));
        for (uint8 i; i < dup; i++) {
            sd[i] = sd[0];
        }
        data = abi.encode(sd);
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

    function testFuzz_validateDataMaxSignatures(bool withUserOp, uint8 excess) public {
        vm.assume(excess > 0);

        Signer[] memory signers = _createSigners(1);
        bytes32 message = keccak256("Signed by signer");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signers[0].pk, ECDSA.toEthSignedMessageHash(message));
        bytes memory signature = abi.encodePacked(r, s, v);

        uint16 count = uint16(type(uint8).max) + excess;
        UserOpMultiSigVerifier.SignerData[] memory sd = new UserOpMultiSigVerifier.SignerData[](count);
        for (uint16 i = 0; i < count; i++) {
            sd[i] = UserOpMultiSigVerifier.SignerData({
                // Note: index will overflow back to 0 after max uint8.
                // This is ok since a MaxSignaturesExceeded() error is expected.
                index: 0,
                signature: signature
            });
        }

        bytes memory data = abi.encode(sd);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = data;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        bytes memory config = _createConfig(1, signers);

        vm.expectRevert(UserOpMultiSigVerifier.MaxSignaturesExceeded.selector);
        verifier.validateData(message, data, config);
    }

    function testFuzz_validateDataInvalidCaller(address keystore) public {
        vm.assume(keystore != address(this));
        vm.prank(keystore);
        vm.expectRevert(OnlyKeystore.NotFromKeystore.selector);
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

    function _getSizeAndAssumeMaxOwnerLimitExceeded(uint8 threshold, uint8 offset, uint8 excess)
        internal
        pure
        returns (uint16 size)
    {
        size = uint16(type(uint8).max) + excess;
        vm.assume(threshold > 0 && excess > 0);
        vm.assume(uint16(threshold) + uint16(offset) <= size);
    }

    function _createSigners(uint16 size) internal returns (Signer[] memory) {
        Signer[] memory signers = new Signer[](size);
        for (uint16 i = 0; i < size; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(LibString.toString(i));
            signers[i] = Signer({addr: addr, pk: pk});
        }
        _quickSortSigners(signers, true);
        return signers;
    }

    function _createSignersReverse(uint16 size) internal returns (Signer[] memory) {
        Signer[] memory signers = new Signer[](size);
        for (uint16 i = 0; i < size; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(LibString.toString(i));
            signers[i] = Signer({addr: addr, pk: pk});
        }
        _quickSortSigners(signers, false);
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
            uint16 index = uint16(i) + offset;
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signers[index].pk, ECDSA.toEthSignedMessageHash(message));
            sd[i] = UserOpMultiSigVerifier.SignerData({
                // Note: index will overflow back to 0 after max uint8.
                // This is ok since an InvalidNumberOfOwners() error is expected.
                index: uint8(index),
                signature: abi.encodePacked(r, s, v)
            });
        }

        return abi.encode(sd);
    }

    function _quickSortSigners(Signer[] memory arr, bool asc) internal pure {
        if (arr.length > 1) {
            _quickSortSigners(arr, asc, 0, int256(arr.length) - 1);
        }
    }

    function _quickSortSigners(Signer[] memory arr, bool asc, int256 left, int256 right) private pure {
        if (left >= right) return;

        Signer memory pivot = arr[uint256(left + (right - left) / 2)];
        int256 i = left;
        int256 j = right;

        while (i <= j) {
            if (asc) {
                while (arr[uint256(i)].addr < pivot.addr) i++;
                while (arr[uint256(j)].addr > pivot.addr) j--;
            } else {
                while (arr[uint256(i)].addr > pivot.addr) i++;
                while (arr[uint256(j)].addr < pivot.addr) j--;
            }

            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (arr[uint256(j)], arr[uint256(i)]);
                i++;
                j--;
            }
        }

        if (left < j) _quickSortSigners(arr, asc, left, j);
        if (i < right) _quickSortSigners(arr, asc, i, right);
    }
}
