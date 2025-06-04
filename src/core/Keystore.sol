// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {UpdateAction, ValidationAction} from "../interface/actions.sol";
import {IKeystore} from "../interface/IKeystore.sol";
import {IVerifier} from "../interface/IVerifier.sol";

contract Keystore is IKeystore {
    mapping(bytes32 => bytes32) public rootHashes;
    mapping(bytes32 => bool) internal usedHashes;

    function handleUpdates(UpdateAction[] calldata actions) external {
        for (uint256 i = 0; i < actions.length; i++) {
            UpdateAction calldata action = actions[i];
            if (action.nextHash == action.refHash || usedHashes[action.nextHash]) revert InvalidNextHash();

            bytes32 rootHash = _getCurrentRootHash(action.refHash);
            bytes32 nodeHash = keccak256(action.node);
            if (!MerkleProofLib.verify(action.proof, rootHash, nodeHash)) revert InvalidProof();

            (address verifier, bytes memory config) = _unpackNode(action.node);
            bytes32 message = keccak256(abi.encode(action.refHash, action.nextHash, nodeHash, keccak256(action.data)));
            if (!IVerifier(verifier).validateData(message, action.data, config)) {
                emit RootHashUpdated(action.refHash, rootHash, action.nextHash, false);
            } else {
                rootHashes[action.refHash] = action.nextHash;
                usedHashes[action.nextHash] = true;
                emit RootHashUpdated(action.refHash, rootHash, action.nextHash, true);
            }
        }
    }

    function validate(ValidationAction calldata action) external view returns (bool) {
        bytes32 rootHash = _getCurrentRootHash(action.refHash);
        if (!MerkleProofLib.verify(action.proof, rootHash, keccak256(action.node))) revert InvalidProof();

        (address verifier, bytes memory config) = _unpackNode(action.node);
        return IVerifier(verifier).validateData(action.message, action.data, config);
    }

    function _getCurrentRootHash(bytes32 refHash) internal view returns (bytes32) {
        bytes32 currentHash = rootHashes[refHash];
        return currentHash == bytes32(0) ? refHash : currentHash;
    }

    function _unpackNode(bytes calldata node) internal pure returns (address verifier, bytes memory config) {
        if (node.length < 20) revert InvalidNode();
        else if (node.length > 20) config = bytes(node[20:]);

        verifier = address(bytes20(node[:20]));
        if (verifier == address(0)) {
            revert InvalidVerifier();
        }
    }
}
