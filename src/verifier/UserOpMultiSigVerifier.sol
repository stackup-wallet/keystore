// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {IVerifier} from "../interface/IVerifier.sol";
import {OnlyKeystore} from "../lib/OnlyKeystore.sol";

contract UserOpMultiSigVerifier is IVerifier, OnlyKeystore {
    error ZeroThresholdNotAllowed();
    error InvalidNumberOfOwners();
    error OwnersUnsortedOrHasDuplicates();
    error MaxSignaturesExceeded();

    bytes1 public constant SIGNATURES_ONLY_TAG = 0xff;

    struct SignerData {
        uint8 index;
        bytes signature;
    }

    struct SignatureCheck {
        uint8 valid;
        uint8 invalid;
        bytes32 message;
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
     * validation. It MUST be greater than 0.
     * The owners array is all the valid signers on the multisig. It MUST be greater
     * than or equal to the threshold AND be sorted in ascending order for efficient
     * duplicate detection.
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
        require(owners.length >= threshold && owners.length <= type(uint8).max, InvalidNumberOfOwners());
        _requireSortedAndUnique(owners);

        SignerData[] memory signatures;
        if (bytes1(data[0]) == SIGNATURES_ONLY_TAG) {
            (signatures) = abi.decode(data[1:], (SignerData[]));
        } else {
            PackedUserOperation memory userOp = abi.decode(data, (PackedUserOperation));
            signatures = abi.decode(userOp.signature, (SignerData[]));
        }
        uint256 length = signatures.length;
        require(length <= type(uint8).max, MaxSignaturesExceeded());

        SignatureCheck memory sc;
        sc.message = ECDSA.toEthSignedMessageHash(message);
        bool[] memory seen = new bool[](owners.length);
        for (uint256 i = 0; i < length; i++) {
            SignerData memory sd = signatures[i];

            // Note: we need to ensure gas usage is consistent during simulation with dummy signers.
            !seen[sd.index] && owners[sd.index] == ECDSA.recover(sc.message, sd.signature) ? sc.valid++ : sc.invalid++;
            seen[sd.index] = true;
        }

        return sc.valid >= threshold ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    // ================================================================
    // Helper functions
    // ================================================================

    /**
     * @dev Checks that a sorted owners array is strictly unique (no duplicates).
     * In practice, the upper bound for this function is limited by the maximum
     * number of owners. This is enforced elsewhere to be max uint8 (i.e. 255).
     */
    function _requireSortedAndUnique(address[] memory owners) internal pure {
        uint256 length = owners.length;
        for (uint256 i = 1; i < length; i++) {
            require(owners[i] > owners[i - 1], OwnersUnsortedOrHasDuplicates());
        }
    }
}
