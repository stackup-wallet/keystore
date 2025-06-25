// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

abstract contract ERC1271 {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant ERC1271_VALID_VALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID_VALUE = 0xffffffff;

    function isValidSignature(bytes32 hash, bytes memory signature) public view virtual returns (bytes4 magicValue);
}
