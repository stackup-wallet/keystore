// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {IVerifier} from "../interface/IVerifier.sol";
import {UpdateAction, ValidateAction} from "../lib/Actions.sol";

contract Keystore is IKeystore {
    mapping(bytes32 => mapping(address => bytes32)) internal _rootHash;
    mapping(bytes32 => mapping(uint192 => mapping(address => uint64))) internal _nonceSequence;
    mapping(bytes32 => mapping(bytes32 => mapping(address => bytes))) internal _nodeCache;

    function handleUpdates(UpdateAction[] calldata actions) external {
        for (uint256 i = 0; i < actions.length; i++) {
            UpdateAction calldata action = actions[i];
            (uint192 nonceKey, uint64 nonceSeq) = _unpackNonceKey(action.nonce);
            uint64 currSeq = _validateAndGetNonce(action.refHash, action.account, nonceKey, nonceSeq);

            (bytes32 nodeHash, bytes memory node) =
                _validateNode(action.refHash, action.account, action.proof, action.node);
            (address verifier, bytes memory config) = _unpackNode(node);
            bytes32 message =
                keccak256(abi.encode(action.refHash, action.nextHash, action.account, action.nonce, nodeHash));
            if (IVerifier(verifier).validateData(message, action.data, config) == SIG_VALIDATION_FAILED) {
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, node, action.data, false
                );
            } else {
                _rootHash[action.refHash][action.account] = action.nextHash;
                _incrementNonce(action.refHash, action.account, nonceKey, currSeq);
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, node, action.data, true
                );
            }
        }
    }

    function validate(ValidateAction calldata action) external view returns (uint256 validationData) {
        (, bytes memory node) = _validateNode(action.refHash, msg.sender, action.proof, action.node);

        (address verifier, bytes memory config) = _unpackNode(node);
        return IVerifier(verifier).validateData(action.message, action.data, config);
    }

    function registerNode(bytes32 refHash, bytes32[] calldata proof, bytes calldata node) external {
        require(node.length >= 20, InvalidNode());
        require(address(bytes20(LibBytes.slice(node, 0, 20))) != address(0), InvalidVerifier());

        bytes32 rootHash = _getCurrentRootHash(refHash, msg.sender);
        bytes32 nodeHash = keccak256(node);
        require(MerkleProofLib.verify(proof, rootHash, nodeHash), InvalidProof());

        _nodeCache[rootHash][nodeHash][msg.sender] = node;
    }

    function getRegisteredNode(bytes32 refHash, address account, bytes calldata node)
        external
        view
        returns (bytes memory)
    {
        return _nodeCache[_getCurrentRootHash(refHash, account)][keccak256(node)][account];
    }

    function getRootHash(bytes32 refHash, address account) external view returns (bytes32 rootHash) {
        rootHash = _getCurrentRootHash(refHash, account);
    }

    function getNonce(bytes32 refHash, address account, uint192 key) external view returns (uint256 nonce) {
        return _nonceSequence[refHash][key][account] | (uint256(key) << 64);
    }

    // ================================================================
    // Internal functions
    // ================================================================

    function _unpackNonceKey(uint256 nonce) internal pure returns (uint192 nonceKey, uint64 nonceSeq) {
        nonceKey = uint192(nonce >> 64);
        nonceSeq = uint64(nonce);
    }

    function _validateAndGetNonce(bytes32 refHash, address account, uint192 key, uint64 seq)
        internal
        view
        returns (uint64 currSeq)
    {
        currSeq = _nonceSequence[refHash][key][account];
        require(currSeq == seq, InvalidNonce());
    }

    function _incrementNonce(bytes32 refHash, address account, uint192 key, uint64 currSeq) internal {
        _nonceSequence[refHash][key][account] = currSeq + 1;
    }

    function _getCurrentRootHash(bytes32 refHash, address account) internal view returns (bytes32) {
        bytes32 currRootHash = _rootHash[refHash][account];
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

    function _validateNode(bytes32 refHash, address account, bytes calldata aProof, bytes calldata aNode)
        internal
        view
        returns (bytes32 nodeHash, bytes memory node)
    {
        if (aProof.length == 0) {
            nodeHash = bytes32(aNode);
            node = _nodeCache[_getCurrentRootHash(refHash, account)][nodeHash][account];
            require(node.length >= 20, UnregisteredProof());
        } else {
            nodeHash = keccak256(aNode);
            node = aNode;
            (bytes32[] memory proof) = abi.decode(aProof, (bytes32[]));
            require(MerkleProofLib.verify(proof, _getCurrentRootHash(refHash, account), nodeHash), InvalidProof());
        }
    }
}
