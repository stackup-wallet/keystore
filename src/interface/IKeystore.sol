// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UpdateAction, ValidateAction} from "../lib/Actions.sol";

interface IKeystore {
    error InvalidNonce();
    error InvalidProof();
    error UnregisteredProof();
    error InvalidNode();
    error InvalidVerifier();

    event RootHashUpdated(
        bytes32 indexed refHash, bytes32 nextHash, uint256 nonce, bytes proof, bytes node, bytes data, bool success
    );

    function handleUpdates(UpdateAction[] calldata actions) external;
    function validate(ValidateAction calldata action) external view returns (uint256 validationData);

    function registerNode(bytes32 refHash, bytes32[] calldata proof, bytes calldata node) external;
    function getRegisteredNode(bytes32 refHash, address account, bytes calldata node)
        external
        view
        returns (bytes memory);

    function getRootHash(bytes32 refHash, address account) external view returns (bytes32 rootHash);
    function getNonce(bytes32 refHash, address account, uint192 key) external view returns (uint256 nonce);
}
