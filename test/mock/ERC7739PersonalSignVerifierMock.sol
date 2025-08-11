// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";

import {IVerifier} from "../../src/interface/IVerifier.sol";

contract ERC7739PersonalSignVerifierMock is IVerifier {
    bytes32 private immutable originalHash;

    constructor(bytes32 hash) {
        originalHash = hash;
    }

    function validateData(bytes32 hash, bytes calldata data, bytes calldata) external view returns (uint256) {
        bytes32 finalHash = keccak256(
            abi.encodePacked(
                hex"1901",
                keccak256(
                    abi.encode(
                        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                        keccak256(bytes("KeystoreAccount")),
                        keccak256(bytes("1")),
                        block.chainid,
                        address(bytes20(data))
                    )
                ),
                keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), originalHash))
            )
        );

        return finalHash == hash ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
