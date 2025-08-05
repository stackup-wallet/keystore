// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

contract UserOpMultiSigVerifier is IVerifier, OnlyKeystore {
    error ZeroThresholdNotAllowed();

    bytes1 public constant SIGNATURES_ONLY_TAG = 0xff;

    struct SignerData {
        uint8 index;
        bytes signature;
    }

    constructor(address aKeystore) OnlyKeystore(aKeystore) {}

    /**
     * @notice Called by the Keystore for nodes with multisig ECDSA verification.
     * @dev This function will revert if any of the ECDSA signatures are invalid.
     * During simulation, it is therefore important to ensure all dummy signatures
     * used are structurally valid.
     * @param message The hashed message that must be signed by the owners.
     * @param data The calldata containing the signatures. If the first byte is
     * SIGNATURES_ONLY_TAG (0xff), it is followed by an abi-encoded array of SignerData
     * structs. Otherwise, it is a PackedUserOperation whose signature field contains
     * the abi-encoded array of SignerData.
     * @param config The node configuration, expected to be abi.encoded as
     * (uint8 threshold, address[] owners).
     * The threshold is the minimum number of owner signatures required to pass
     * validation.
     * The owners array is all the valid signers on the multisig.
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
        (uint8 threshold, address[] memory owners) = abi.decode(config, (uint8, address[]));
        require(threshold > 0, ZeroThresholdNotAllowed());

        SignerData[] memory signatures;
        if (bytes1(data[0]) == SIGNATURES_ONLY_TAG) {
            (signatures) = abi.decode(data[1:], (SignerData[]));
        } else {
            PackedUserOperation memory userOp = abi.decode(data, (PackedUserOperation));
            signatures = abi.decode(userOp.signature, (SignerData[]));
        }

        uint8 valid = 0;
        uint8 invalid = 0;
        bool[] memory seen = new bool[](owners.length);
        uint256 length = signatures.length;
        for (uint256 i = 0; i < length; i++) {
            SignerData memory sd = signatures[i];

            // Note: we need to ensure gas usage is consistent during simulation with dummy signers.
            !seen[sd.index] && owners[sd.index] == ECDSA.recover(message, sd.signature) ? valid++ : invalid++;
            seen[sd.index] = true;
        }

        return valid >= threshold ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
