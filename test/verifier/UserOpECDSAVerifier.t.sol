// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {OnlyKeystore} from "../../src/lib/OnlyKeystore.sol";
import {UserOpECDSAVerifier} from "../../src/verifier/UserOpECDSAVerifier.sol";

contract UserOpECDSAVerifierTest is Test {
    UserOpECDSAVerifier public verifier;

    function setUp() public {
        verifier = new UserOpECDSAVerifier(address(this));
    }

    function testFuzz_validateData(bool withUserOp) public {
        (address signer, uint256 signerPK) = makeAddrAndKey("signer");
        bytes32 message = keccak256("Signed by signer");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK, message);

        bytes memory data = abi.encodePacked(r, s, v);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = abi.encodePacked(r, s, v);
            data = abi.encode(userOp);
        }

        uint256 validationData = verifier.validateData(message, data, abi.encodePacked(signer));
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function testFuzz_validateDataValidationFailed(bool withUserOp, address config) public {
        (, uint256 signerPK) = makeAddrAndKey("signer");
        bytes32 message = keccak256("Signed by signer");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK, message);

        bytes memory data = abi.encodePacked(r, s, v);
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = abi.encodePacked(r, s, v);
            data = abi.encode(userOp);
        }

        uint256 validationData = verifier.validateData(message, data, abi.encodePacked(config));
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testFuzz_validateDataInvalidCaller(address keystore) public {
        vm.assume(keystore != address(this));
        vm.prank(keystore);
        vm.expectRevert(OnlyKeystore.NotFromKeystore.selector);
        verifier.validateData(0, "", "");
    }

    function testFuzz_validateDataInvalidData(bytes calldata data) public {
        vm.assume(data.length < 64);
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        verifier.validateData(0, data, "");
    }
}
