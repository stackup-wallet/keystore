// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {ValidateAction} from "../lib/Actions.sol";

library KeystoreUserOperation {
    function unpackSignature(PackedUserOperation calldata userOp)
        internal
        pure
        returns (bytes32[] memory proof, bytes memory node, bytes memory signature)
    {
        (proof, node, signature) = abi.decode(userOp.signature, (bytes32[], bytes, bytes));
    }

    function encodeValidateActionData(PackedUserOperation calldata userOp, bytes memory signature)
        internal
        pure
        returns (bytes memory data)
    {
        data = abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.accountGasLimits,
            userOp.preVerificationGas,
            userOp.gasFees,
            userOp.paymasterAndData,
            signature
        );
    }

    function prepareValidateAction(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes32 refHash)
        internal
        pure
        returns (ValidateAction memory)
    {
        (bytes32[] memory proof, bytes memory node, bytes memory signature) = unpackSignature(userOp);
        bytes memory data = encodeValidateActionData(userOp, signature);

        return ValidateAction({refHash: refHash, message: userOpHash, proof: proof, node: node, data: data});
    }
}
