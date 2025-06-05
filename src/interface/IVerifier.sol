// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IVerifier {
    function validateData(bytes32 message, bytes calldata data, bytes calldata config)
        external
        view
        returns (uint256 validationData);
}
