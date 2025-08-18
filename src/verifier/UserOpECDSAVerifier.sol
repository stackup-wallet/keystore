// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

contract UserOpECDSAVerifier is IVerifier, OnlyKeystore {
    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    /**
     * @notice Called by the Keystore for nodes with ECDSA verification.
     * @dev This function will revert if the ECDSA signature is invalid. During
     * simulation, it is therefore important to ensure the dummy signature used
     * is structurally valid.
     * @param message The hashed message that was signed.
     * @param data The raw signature or a PackedUserOperation containing the signature.
     * If the length is more than 65 bytes, it will be decoded as a PackedUserOperation
     * with the userop.signature field containing the packed (r,s,v) signature values.
     * @param config The node configuration, expected to contain the 20 bytes ECDSA
     * signer address.
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
