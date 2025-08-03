// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

/**
 * @dev This contract depends on the Solady P256.sol library which itself has a
 * dependency on a VERIFIER and CANARY contract to properly handle the case where
 * the RIP-7212 precompile might or might not be present.
 * See https://github.com/Vectorized/solady/blob/v0.1.19/src/utils/P256.sol for details.
 */
contract UserOpWebAuthnCosignVerifier is IVerifier, OnlyKeystore {
    bytes1 public constant SIGNATURES_ONLY_TAG = 0xff;

    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    function validateData(bytes32 message, bytes calldata data, bytes calldata config)
        external
        view
        override
        onlyKeystore
        returns (uint256 validationData)
    {
        bytes memory ecdsaSignature;
        bytes memory webauthnData;
        if (bytes1(data[0]) == SIGNATURES_ONLY_TAG) {
            (ecdsaSignature, webauthnData) = abi.decode(data[1:], (bytes, bytes));
        } else {
            PackedUserOperation memory userOp = abi.decode(data, (PackedUserOperation));
            (ecdsaSignature, webauthnData) = abi.decode(userOp.signature, (bytes, bytes));
        }

        (address cosigner, bytes32 x, bytes32 y) = abi.decode(config, (address, bytes32, bytes32));
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.tryDecodeAuth(webauthnData);

        // Note: always run verification for both signatures in order to calculate accurate gas
        // estimates during simulation with dummy signers.
        bool cosignValid = cosigner == ECDSA.recover(message, ecdsaSignature);
        bool webauthnValid = WebAuthn.verify(abi.encode(message), true, auth, x, y);
        return (cosignValid && webauthnValid) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
