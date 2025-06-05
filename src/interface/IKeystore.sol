// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {UpdateAction, ValidateAction} from "./actions.sol";

interface IKeystore {
    error InvalidNonce();
    error InvalidProof();
    error InvalidVerification();
    error InvalidNode();
    error InvalidVerifier();

    event RootHashUpdated(
        bytes32 indexed refHash, bytes32 nextHash, uint256 nonce, bytes32[] proof, bytes node, bytes data, bool success
    );

    function handleUpdates(UpdateAction[] calldata actions) external;
    function validate(ValidateAction calldata action) external view returns (bool);
}
