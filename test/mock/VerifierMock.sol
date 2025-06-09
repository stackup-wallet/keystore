// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "../../src/interface/IVerifier.sol";

contract VerifierMock is IVerifier {
    uint256 private immutable validationData;

    constructor(uint256 vd) {
        validationData = vd;
    }

    function validateData(bytes32, bytes calldata, bytes calldata) external view returns (uint256) {
        return validationData;
    }
}
