// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {ValidateAction} from "../lib/Actions.sol";

library KeystoreUserOperation {
    function unpackOriginalUserOpSignature(bytes calldata userOpSignature)
        internal
        pure
        returns (bytes32[] memory proof, bytes memory node, bytes memory signature)
    {
        (proof, node, signature) = abi.decode(userOpSignature, (bytes32[], bytes, bytes));
    }

    function repackUserOpForValidateAction(PackedUserOperation calldata userOp, bytes memory signature)
        internal
        pure
        returns (bytes memory data)
    {
        PackedUserOperation memory newUserOp = PackedUserOperation({
            sender: userOp.sender,
            nonce: userOp.nonce,
            initCode: userOp.initCode,
            callData: userOp.callData,
            accountGasLimits: userOp.accountGasLimits,
            preVerificationGas: userOp.preVerificationGas,
            gasFees: userOp.gasFees,
            paymasterAndData: userOp.paymasterAndData,
            signature: signature
        });
        data = abi.encode(newUserOp);
    }

    function prepareValidateAction(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes32 refHash)
        internal
        pure
        returns (ValidateAction memory)
    {
        (bytes32[] memory proof, bytes memory node, bytes memory signature) =
            unpackOriginalUserOpSignature(userOp.signature);
        bytes memory data = repackUserOpForValidateAction(userOp, signature);

        return ValidateAction({refHash: refHash, message: userOpHash, proof: proof, node: node, data: data});
    }
}
