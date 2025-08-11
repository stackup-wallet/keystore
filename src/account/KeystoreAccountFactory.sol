// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ISenderCreator} from "account-abstraction/interfaces/ISenderCreator.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {KeystoreAccount} from "./KeystoreAccount.sol";

/**
 * @dev This factory uses ERC-1167 minimal proxies to deploy each instance of a
 * KeystoreAccount. For maximum simplicity, the KeystoreAccount does NOT have a
 * built-in path for upgradability.
 */
contract KeystoreAccountFactory {
    error NotFromSenderCreator();

    KeystoreAccount public immutable accountImplementation;
    IEntryPoint public immutable entryPoint;
    ISenderCreator public immutable senderCreator;

    constructor(IEntryPoint _entryPoint, IKeystore _keystore) {
        accountImplementation = new KeystoreAccount(_entryPoint, _keystore);
        entryPoint = _entryPoint;
        senderCreator = _entryPoint.senderCreator();
    }

    /**
     * @dev refHash may not be unique for every account if the same initial
     * UserConfiguration Merkle Tree is used. In this case a unique salt value
     * must be used to avoid address collision.
     */
    function createAccount(bytes32 refHash, uint256 salt) public returns (KeystoreAccount ret) {
        require(msg.sender == address(senderCreator), NotFromSenderCreator());
        address addr = getAddress(refHash, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return KeystoreAccount(payable(addr));
        }
        address deployed =
            LibClone.cloneDeterministic(address(accountImplementation), keccak256(abi.encode(refHash, salt)));
        ret = KeystoreAccount(payable(deployed));
        ret.initialize(refHash);
    }

    function getAddress(bytes32 refHash, uint256 salt) public view returns (address) {
        return LibClone.predictDeterministicAddress(
            address(accountImplementation), keccak256(abi.encode(refHash, salt)), address(this)
        );
    }

    function addPermanentEntryPointStake() external payable {
        entryPoint.addStake{value: msg.value}(type(uint32).max);
    }
}
