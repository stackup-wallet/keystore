// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {Test} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";

import {UserOpMultiSigVerifier} from "../../src/verifier/UserOpMultiSigVerifier.sol";

contract UserOpMultiSigVerifierNofM is Test {
    UserOpMultiSigVerifier public verifier;

    struct Signer {
        address addr;
        uint256 pk;
    }

    function setUp() public {
        verifier = new UserOpMultiSigVerifier(address(this));
    }

    function test_validateData1of1() public {
        uint8 n = 1;
        uint8 m = 2;
        Signer[] memory signers = _createSigners(m);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), _createData(message, n, 0, signers));
        bytes memory config = _createConfig(n, signers);

        vm.startSnapshotGas("1. 1/2 multisig");
        uint256 validationData = verifier.validateData(message, data, config);
        vm.stopSnapshotGas();
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function test_validateData2of3() public {
        uint8 n = 2;
        uint8 m = 3;
        Signer[] memory signers = _createSigners(m);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), _createData(message, n, 0, signers));
        bytes memory config = _createConfig(n, signers);

        vm.startSnapshotGas("2. 2/3 multisig");
        uint256 validationData = verifier.validateData(message, data, config);
        vm.stopSnapshotGas();
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function test_validateData3of5() public {
        uint8 n = 3;
        uint8 m = 5;
        Signer[] memory signers = _createSigners(m);

        bytes32 message = keccak256("Signed by signer");
        bytes memory data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), _createData(message, n, 0, signers));
        bytes memory config = _createConfig(n, signers);

        vm.startSnapshotGas("3. 3/5 multisig");
        uint256 validationData = verifier.validateData(message, data, config);
        vm.stopSnapshotGas();
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    // ================================================================
    // Helper functions
    // ================================================================

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
