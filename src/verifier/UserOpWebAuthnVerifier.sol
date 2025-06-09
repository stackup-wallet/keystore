// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

import {IVerifier} from "../interface/IVerifier.sol";

contract UserOpWebAuthnVerifier is IVerifier {
    address public immutable keystore;

    modifier onlyKeystore() {
        require(msg.sender == keystore, "verifier: not from Keystore");
        _;
    }

    constructor(address aKeystore) {
        keystore = aKeystore;
    }

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

        bytes memory challenge = abi.encode(message);
        bytes32 p256X = bytes32(LibBytes.slice(config, 0, 32));
        bytes32 p256Y = bytes32(LibBytes.slice(config, 32, 64));

        return WebAuthn.verify(challenge, true, auth, p256X, p256Y) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
