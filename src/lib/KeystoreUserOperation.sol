// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {ValidateAction} from "../interface/Actions.sol";

library KeystoreUserOperation {
    function prepareValidateAction(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes32 refHash)
        internal
        pure
        returns (ValidateAction memory)
    {
        (bytes32[] memory proof, bytes memory node, bytes memory signature) =
            abi.decode(userOp.signature, (bytes32[], bytes, bytes));
        bytes memory data = abi.encode(
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

        return ValidateAction({refHash: refHash, message: userOpHash, proof: proof, node: node, data: data});
    }
}
