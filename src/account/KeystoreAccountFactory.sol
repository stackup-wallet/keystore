// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ISenderCreator} from "account-abstraction/interfaces/ISenderCreator.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {KeystoreAccount} from "./KeystoreAccount.sol";

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

    function createAccount(bytes32 refHash, uint256 salt) public returns (KeystoreAccount ret) {
        require(msg.sender == address(senderCreator), NotFromSenderCreator());
        address addr = getAddress(refHash, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return KeystoreAccount(payable(addr));
        }
        ret = KeystoreAccount(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(accountImplementation), abi.encodeCall(KeystoreAccount.initialize, (refHash))
                )
            )
        );
    }

    function getAddress(bytes32 refHash, uint256 salt) public view returns (address) {
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(address(accountImplementation), abi.encodeCall(KeystoreAccount.initialize, (refHash)))
                )
            )
        );
    }

    function addPermanentEntryPointStake() external payable {
        entryPoint.addStake{value: msg.value}(type(uint32).max);
    }
}
