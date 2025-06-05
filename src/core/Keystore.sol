// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {IVerifier} from "../interface/IVerifier.sol";
import {UpdateAction, ValidateAction} from "../lib/Actions.sol";

contract Keystore is IKeystore {
    mapping(bytes32 => bytes32) public rootHash;
    mapping(bytes32 => mapping(uint192 => uint256)) public nonceSequence;

    function handleUpdates(UpdateAction[] calldata actions) external {
        for (uint256 i = 0; i < actions.length; i++) {
            UpdateAction calldata action = actions[i];
            (uint192 nonceKey, uint64 nonceSeq) = _unpackNonceKey(action.nonce);
            require(_validateNonce(action.refHash, nonceKey, nonceSeq), InvalidNonce());

            bytes32 nodeHash = keccak256(action.node);
            require(MerkleProofLib.verify(action.proof, _getCurrentRootHash(action.refHash), nodeHash), InvalidProof());

            (address verifier, bytes memory config) = _unpackNode(action.node);
            bytes32 message = keccak256(abi.encode(action.refHash, action.nextHash, action.nonce, nodeHash));
            if (IVerifier(verifier).validateData(message, action.data, config) != SIG_VALIDATION_FAILED) {
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, action.node, action.data, false
                );
            } else {
                rootHash[action.refHash] = action.nextHash;
                _updateNonce(action.refHash, nonceKey);
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, action.node, action.data, true
                );
            }
        }
    }

    function validate(ValidateAction calldata action) external view returns (uint256 validationData) {
        require(
            MerkleProofLib.verify(action.proof, _getCurrentRootHash(action.refHash), keccak256(action.node)),
            InvalidProof()
        );

        (address verifier, bytes memory config) = _unpackNode(action.node);
        return IVerifier(verifier).validateData(action.message, action.data, config);
    }

    function getNonce(bytes32 refHash, uint192 key) public view returns (uint256 nonce) {
        return nonceSequence[refHash][key] | (uint256(key) << 64);
    }

    function _unpackNonceKey(uint256 nonce) internal pure returns (uint192 nonceKey, uint64 nonceSeq) {
        nonceKey = uint192(nonce >> 64);
        nonceSeq = uint64(nonce);
    }

    function _validateNonce(bytes32 refHash, uint192 key, uint64 seq) internal view returns (bool) {
        return nonceSequence[refHash][key] == seq;
    }

    function _updateNonce(bytes32 refHash, uint192 key) internal {
        nonceSequence[refHash][key]++;
    }

    function _getCurrentRootHash(bytes32 refHash) internal view returns (bytes32) {
        bytes32 currRootHash = rootHash[refHash];
        return currRootHash == bytes32(0) ? refHash : currRootHash;
    }

    function _unpackNode(bytes memory node) internal pure returns (address verifier, bytes memory config) {
        if (node.length < 20) revert InvalidNode();
        else if (node.length > 20) config = LibBytes.slice(node, 20, node.length);

        verifier = address(bytes20(LibBytes.slice(node, 0, 20)));
        if (verifier == address(0)) {
            revert InvalidVerifier();
        }
    }
}
