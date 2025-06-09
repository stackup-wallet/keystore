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
    mapping(bytes32 => mapping(bytes32 => mapping(address => bool))) internal _proofCache;

    function handleUpdates(UpdateAction[] calldata actions) external {
        for (uint256 i = 0; i < actions.length; i++) {
            UpdateAction calldata action = actions[i];
            (uint192 nonceKey, uint64 nonceSeq) = _unpackNonceKey(action.nonce);
            require(_validateNonce(action.refHash, action.account, nonceKey, nonceSeq), InvalidNonce());

            bytes32 nodeHash = keccak256(action.node);
            _validateProof(action.refHash, action.account, action.proof, nodeHash);

            (address verifier, bytes memory config) = _unpackNode(action.node);
            bytes32 message =
                keccak256(abi.encode(action.refHash, action.nextHash, action.account, action.nonce, nodeHash));
            if (IVerifier(verifier).validateData(message, action.data, config) == SIG_VALIDATION_FAILED) {
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, action.node, action.data, false
                );
            } else {
                _rootHash[action.refHash][msg.sender] = action.nextHash;
                _updateNonce(action.refHash, action.account, nonceKey);
                emit RootHashUpdated(
                    action.refHash, action.nextHash, action.nonce, action.proof, action.node, action.data, true
                );
            }
        }
    }

    function validate(ValidateAction calldata action) external view returns (uint256 validationData) {
        _validateProof(action.refHash, msg.sender, action.proof, keccak256(action.node));

        (address verifier, bytes memory config) = _unpackNode(action.node);
        return IVerifier(verifier).validateData(action.message, action.data, config);
    }

    function registerProof(bytes32 refHash, bytes32[] calldata proof, bytes calldata node) external {
        bytes32 rootHash = _getCurrentRootHash(refHash, msg.sender);
        bytes32 nodeHash = keccak256(node);
        require(MerkleProofLib.verify(proof, rootHash, nodeHash), InvalidProof());

        _proofCache[rootHash][nodeHash][msg.sender] = true;
    }

    function proofRegistered(bytes32 refHash, address account, bytes calldata node) external view returns (bool) {
        return _proofCache[_getCurrentRootHash(refHash, account)][keccak256(node)][account];
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

    function _validateNonce(bytes32 refHash, address account, uint192 key, uint64 seq) internal view returns (bool) {
        return _nonceSequence[refHash][key][account] == seq;
    }

    function _updateNonce(bytes32 refHash, address account, uint192 key) internal {
        _nonceSequence[refHash][key][account]++;
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

    function _validateProof(bytes32 refHash, address account, bytes calldata aProof, bytes32 nodeHash) internal view {
        if (aProof.length == 0) {
            require(_proofCache[_getCurrentRootHash(refHash, account)][nodeHash][account], UnregisteredProof());
        } else {
            (bytes32[] memory proof) = abi.decode(aProof, (bytes32[]));
            require(MerkleProofLib.verify(proof, _getCurrentRootHash(refHash, account), nodeHash), InvalidProof());
        }
    }
}
