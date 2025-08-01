// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

contract UserOpECDSAVerifier is IVerifier, OnlyKeystore {
    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    function validateData(bytes32 message, bytes calldata data, bytes calldata config)
        external
        view
        override
        onlyKeystore
        returns (uint256 validationData)
    {
        bytes memory signature = data;
        if (signature.length > 65) {
            PackedUserOperation memory userOp = abi.decode(data, (PackedUserOperation));
            signature = userOp.signature;
        }

        return address(bytes20(config)) == ECDSA.recover(message, signature)
            ? SIG_VALIDATION_SUCCESS
            : SIG_VALIDATION_FAILED;
    }
}
