// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";

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

    function testFuzz_addPermanentEntryPointStake(uint32 unstakeDelaySec, uint112 value) public {
        vm.assume(unstakeDelaySec > 0 && value > 0);
        vm.deal(address(this), value);
        factory.addPermanentEntryPointStake{value: value}(unstakeDelaySec);

        IStakeManager.DepositInfo memory stake = entryPoint.getDepositInfo(address(factory));
        assertEq(stake.deposit, 0);
        assertEq(stake.staked, true);
        assertEq(stake.stake, value);
        assertEq(stake.unstakeDelaySec, unstakeDelaySec);
        assertEq(stake.withdrawTime, 0);
    }

    function testFuzz_createAccount(bytes32 refHash, uint256 salt) public {
        address expectedAddr = factory.getAddress(refHash, salt);

        vm.prank(address(entryPoint.senderCreator()));
        address actualAddress = address(factory.createAccount(refHash, salt));

        assertEq(expectedAddr, actualAddress);
    }

    function testFuzz_createAccountAlreadyDeployed(bytes32 refHash, uint256 salt) public {
        address expectedAddr = factory.getAddress(refHash, salt);

        vm.prank(address(entryPoint.senderCreator()));
        factory.createAccount(refHash, salt);

        vm.prank(address(entryPoint.senderCreator()));
        address actualAddress = address(factory.createAccount(refHash, salt));

        assertEq(expectedAddr, actualAddress);
    }

    function testFuzz_createAccountInvalidCaller(bytes32 refHash, uint256 salt, address caller) public {
        vm.assume(caller != address(entryPoint.senderCreator()));

        vm.prank(caller);
        vm.expectRevert(KeystoreAccountFactory.NotFromSenderCreator.selector);
        factory.createAccount(refHash, salt);
    }
}
