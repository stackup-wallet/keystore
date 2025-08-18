// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

/**
 * @dev This contract depends on the Solady P256.sol library which itself has a
 * dependency on a VERIFIER and CANARY contract to properly handle the case where
 * the RIP-7212 precompile might or might not be present.
 * See https://github.com/Vectorized/solady/blob/v0.1.19/src/utils/P256.sol for details.
 */
contract UserOpWebAuthnVerifier is IVerifier, OnlyKeystore {
    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    /**
     * @notice Called by the Keystore for nodes with WebAuthn verification.
     * @param message The hashed message that must be signed by the WebAuthn
     * authenticator.
     * @param data The calldata containing the WebAuthn authentication data. If
     * the data is not a valid WebAuthnAuth struct, it is assumed to be a PackedUserOperation
     * whose signature field contains the WebAuthnAuth encoded bytes.
     * See https://github.com/Vectorized/solady/blob/v0.1.19/src/utils/WebAuthn.sol
     * for details on how WebAuthnAuth is encoded.
     * @param config The node configuration, expected to be abi.encoded as
     * (bytes32 x, bytes32 y), where x and y are the WebAuthn public key coordinates.
     * @return validationData Returns SIG_VALIDATION_SUCCESS (0) if ok, otherwise
     * SIG_VALIDATION_FAILED (1).
     */
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
