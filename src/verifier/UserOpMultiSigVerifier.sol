// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {IVerifier} from "../interface/IVerifier.sol";

contract UserOpMultiSigVerifier is IVerifier {
    bytes1 public constant SIGNATURES_ONLY_TAG = 0xff;
    address public immutable keystore;

    struct SignerData {
        uint8 index;
        bytes signature;
    }

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
        (uint8 threshold, address[] memory owners) = abi.decode(config, (uint8, address[]));
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
