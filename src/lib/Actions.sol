// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

struct UpdateAction {
    bytes32 refHash;
    bytes32 nextHash;
    uint256 nonce;
    bool useChainId;
    address account;
    bytes proof;
    bytes node;
    bytes data;
    bytes nextProof;
    bytes nextNode;
    bytes nextData;
}

struct ValidateAction {
    bytes32 refHash;
    bytes32 message;
    bytes proof;
    bytes node;
    bytes data;
}
