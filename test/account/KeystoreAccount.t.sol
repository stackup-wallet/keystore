// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";

import {ERC7739PersonalSignVerifierMock} from "../mock/ERC7739PersonalSignVerifierMock.sol";
import {ERC7739TypedDataSignVerifierMock} from "../mock/ERC7739TypedDataSignVerifierMock.sol";
import {VerifierMock} from "../mock/VerifierMock.sol";
import {KeystoreAccount} from "../../src/account/KeystoreAccount.sol";
import {KeystoreAccountFactory} from "../../src/account/KeystoreAccountFactory.sol";
import {Keystore} from "../../src/core/Keystore.sol";
import {IKeystore} from "../../src/interface/IKeystore.sol";

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

    function testFuzz_ERC7739SupportDetection(bytes32 refHash) public {
        KeystoreAccount account = _createAccount(refHash);
        assertEq(
            account.isValidSignature(0x7739773977397739773977397739773977397739773977397739773977397739, ""),
            bytes4(0x77390001)
        );
    }

    function test_erc1271SignerReverts() public {
        KeystoreAccountHarness acc = new KeystoreAccountHarness(entryPoint, keystore);
        vm.expectRevert(KeystoreAccount.ERC1271SignerUnused.selector);
        acc.expose_erc1271Signer();
    }

    function testFuzz_isValidSignatureSuccess(bytes32 message, uint256 validationData, bytes calldata data) public {
        vm.assume(validationData != SIG_VALIDATION_FAILED);
        bytes memory node = abi.encodePacked(address(new VerifierMock(validationData)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);
        bytes memory signature = abi.encode(proof, node, data);

        KeystoreAccount account = _createAccount(root);
        assertEq(account.isValidSignature(message, signature), bytes4(0x1626ba7e));
    }

    function testFuzz_isValidSignaturePersonalSignRehash(bytes32 message) public {
        bytes memory node = abi.encodePacked(address(new ERC7739PersonalSignVerifierMock(message)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);

        KeystoreAccount account = _createAccount(root);
        bytes memory data = bytes.concat(bytes20(address(account)));
        bytes memory signature = abi.encodePacked(abi.encode(proof, node, data));

        assertEq(account.isValidSignature(message, signature), bytes4(0x1626ba7e));
    }

    function testFuzz_isValidSignatureTypedDataSignRehash(bytes32 appDomainSeparator, bytes32 contents) public {
        ERC7739TypedDataSignVerifierMock verifier = new ERC7739TypedDataSignVerifierMock(appDomainSeparator, contents);
        bytes memory node = abi.encodePacked(address(verifier));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);

        KeystoreAccount account = _createAccount(root);
        bytes32 typedMessage = keccak256(abi.encodePacked(hex"1901", appDomainSeparator, contents));
        bytes memory data = bytes.concat(bytes20(address(account)));
        bytes memory typedSignature = abi.encodePacked(
            abi.encode(proof, node, data), // original signature
            appDomainSeparator,
            contents,
            bytes(verifier.implicitContentsDesc()),
            uint16(bytes(verifier.implicitContentsDesc()).length)
        );

        assertEq(account.isValidSignature(typedMessage, typedSignature), bytes4(0x1626ba7e));
    }

    function testFuzz_isValidSignatureFailed(bytes32 message, bytes calldata data) public {
        // Use a non-zero gas price to ensure Solady's ERC1271 contract skips the
        // gas burn.
        vm.txGasPrice(1);

        bytes memory node = abi.encodePacked(address(new VerifierMock(SIG_VALIDATION_FAILED)));
        (bytes32 root, bytes memory proof) = _generateUCMT(node);
        bytes memory signature = abi.encode(proof, node, data);

        KeystoreAccount account = _createAccount(root);
        assertEq(account.isValidSignature(message, signature), bytes4(0xffffffff));
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

contract KeystoreAccountHarness is KeystoreAccount {
    constructor(IEntryPoint e, IKeystore k) KeystoreAccount(e, k) {}

    function expose_erc1271Signer() external pure returns (address) {
        return _erc1271Signer();
    }
}
