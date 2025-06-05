// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract ERC1271 {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    function isValidSignature(bytes32 hash, bytes memory signature) public view virtual returns (bytes4 magicValue);
}
