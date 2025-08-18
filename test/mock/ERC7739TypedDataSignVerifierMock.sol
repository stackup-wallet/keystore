// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {LibString} from "solady/utils/LibString.sol";

import {IVerifier} from "../../src/interface/IVerifier.sol";

contract ERC7739TypedDataSignVerifierMock is IVerifier {
    bytes32 private immutable appDomainSeparator;
    bytes32 private immutable contents;
    string public contentsName = "SomeContents";
    string public contentsType = "(bytes32 stuff)";
    string public implicitContentsDesc = string(bytes.concat(bytes(contentsName), bytes(contentsType)));

    constructor(bytes32 _appDomainSeparator, bytes32 _contents) {
        appDomainSeparator = _appDomainSeparator;
        contents = _contents;
    }

    function validateData(bytes32 hash, bytes calldata data, bytes calldata) external view returns (uint256) {
        bytes32 finalHash = keccak256(
            abi.encodePacked(
                hex"1901",
                appDomainSeparator,
                keccak256(
                    abi.encode(
                        keccak256(
                            bytes.concat(
                                bytes("TypedDataSign("),
                                bytes(contentsName),
                                bytes(
                                    " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                                ),
                                bytes(implicitContentsDesc)
                            )
                        ),
                        contents,
                        keccak256(bytes("KeystoreAccount")),
                        keccak256(bytes("1")),
                        block.chainid,
                        address(bytes20(data)),
                        bytes32(0)
                    )
                )
            )
        );

        return finalHash == hash ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }
}
