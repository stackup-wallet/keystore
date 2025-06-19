// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";

import {VerifierMock} from "../mock/VerifierMock.sol";
import {KeystoreAccount} from "../../src/account/KeystoreAccount.sol";
import {KeystoreAccountFactory} from "../../src/account/KeystoreAccountFactory.sol";
import {Keystore} from "../../src/core/Keystore.sol";

contract KeystoreAccountFactoryTest is Test {
    EntryPoint public entryPoint;
    Keystore public keystore;
    KeystoreAccountFactory public factory;

    function setUp() public {
        entryPoint = new EntryPoint();
        keystore = new Keystore();
        factory = new KeystoreAccountFactory(entryPoint, keystore);
    }

    function testFuzz_keystoreAccountInitialized(bytes32 refHash) public {
        vm.expectEmit();
        emit KeystoreAccount.KeystoreAccountInitialized(entryPoint, keystore, refHash);
        _createAccount(refHash);
    }

    function testFuzz_entryPoint(bytes32 refHash) public {
        KeystoreAccount account = _createAccount(refHash);
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function testFuzz_keystore(bytes32 refHash) public {
        KeystoreAccount account = _createAccount(refHash);
        assertEq(address(account.keystore()), address(keystore));
    }

    function testFuzz_isValidSignatureSuccess(bytes32 message, uint256 validationData, bytes calldata data) public {
        vm.assume(validationData != SIG_VALIDATION_FAILED);
        bytes memory node = abi.encodePacked(address(new VerifierMock(validationData)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);
        bytes memory signature = abi.encode(proof, node, data);

        KeystoreAccount account = _createAccount(root);
        assertEq(account.isValidSignature(message, signature), bytes4(0x1626ba7e));
    }

    function testFuzz_isValidSignatureFailed(bytes32 message, bytes calldata data) public {
        bytes memory node = abi.encodePacked(address(new VerifierMock(SIG_VALIDATION_FAILED)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);
        bytes memory signature = abi.encode(proof, node, data);

        KeystoreAccount account = _createAccount(root);
        assertEq(account.isValidSignature(message, signature), bytes4(0x00000000));
    }

    function testFuzz_validateUserOp(
        bytes32 message,
        uint256 missingAccountFunds,
        uint256 validationData,
        bytes calldata data
    ) public {
        bytes memory node = abi.encodePacked(address(new VerifierMock(validationData)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);
        PackedUserOperation memory userOp;
        userOp.signature = abi.encode(proof, node, data);

        IAccount account = _createAccount(root);

        // Initial validation with proof registration
        vm.deal(address(account), missingAccountFunds);
        vm.prank(address(entryPoint));
        assertEq(account.validateUserOp(userOp, message, missingAccountFunds), validationData);

        // Subsequent validation with registered proof
        vm.deal(address(account), missingAccountFunds);
        userOp.signature = abi.encode("", abi.encode(keccak256(node)), data);
        vm.prank(address(entryPoint));
        assertEq(account.validateUserOp(userOp, message, missingAccountFunds), validationData);
    }

    function testFuzz_deposit(bytes32 refHash, uint256 value) public {
        vm.deal(address(this), value);
        KeystoreAccount account = _createAccount(refHash);

        assertEq(address(account).balance, 0);
        assertEq(account.getDeposit(), 0);

        account.addDeposit{value: value}();
        assertEq(address(account).balance, 0);
        assertEq(account.getDeposit(), value);

        vm.prank(address(entryPoint));
        account.withdrawDepositTo(payable(account), value);
        assertEq(address(account).balance, value);
        assertEq(account.getDeposit(), 0);
    }

    // ================================================================
    // Helper functions
    // ================================================================

    function _createAccount(bytes32 refHash) internal returns (KeystoreAccount) {
        vm.prank(address(entryPoint.senderCreator()));
        return factory.createAccount(refHash, 0);
    }

    function _generateUCMT(bytes memory node) internal pure returns (bytes32 root, bytes memory proof) {
        bytes32[] memory proofArray = new bytes32[](0);
        root = keccak256(node);
        proof = abi.encode(proofArray);
    }
}
