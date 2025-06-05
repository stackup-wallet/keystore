// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

struct UpdateAction {
    bytes32 refHash;
    bytes32 nextHash;
    uint256 nonce;
    bytes32[] proof;
    bytes node;
    bytes data;
}

struct ValidateAction {
    bytes32 refHash;
    bytes32 message;
    bytes32[] proof;
    bytes node;
    bytes data;
}
