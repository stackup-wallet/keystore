// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

contract UserOpWebAuthnVerifier is IVerifier, OnlyKeystore {
    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    function validateData(bytes32 message, bytes calldata data, bytes calldata config)
        external
        view
        override
        onlyKeystore
        returns (uint256 validationData)
    {
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(data);
        if (bytes(auth.clientDataJSON).length == 0) {
            PackedUserOperation memory userOp = abi.decode(data, (PackedUserOperation));
            auth = WebAuthn.tryDecodeAuth(userOp.signature);
        }

        (bytes32 x, bytes32 y) = abi.decode(config, (bytes32, bytes32));
        return WebAuthn.verify(abi.encode(message), true, auth, x, y) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
