// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract OnlyKeystore {
    error NotFromKeystore();

    address public immutable keystore;

    constructor(address aKeystore) {
        keystore = aKeystore;
    }

    modifier onlyKeystore() {
        require(msg.sender == keystore, NotFromKeystore());
        _;
    }
}
