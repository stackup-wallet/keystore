// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {UpdateAction, ValidateAction} from "./actions.sol";

interface IKeystore {
    error InvalidNextHash();
    error InvalidProof();
    error InvalidNode();
    error InvalidVerifier();

    event RootHashUpdated(bytes32 indexed refHash, bytes32 oldRoot, bytes32 newRoot, bool success);

    function handleUpdates(UpdateAction[] calldata actions) external;
    function validate(ValidateAction calldata action) external view returns (bool);
}
