// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {UserOpWebAuthnCosignVerifier} from "src/verifier/UserOpWebAuthnCosignVerifier.sol";

contract Deploy is Script {
    function run() public {
        address keystore = 0x18c90BdFc5667D11605ebde82E5E9CDC4D789363;

        vm.startBroadcast();
        UserOpWebAuthnCosignVerifier verifier = new UserOpWebAuthnCosignVerifier{salt: 0}(keystore);
        vm.stopBroadcast();

        console.log("Deploying UserOpWebAuthnCosignVerifier at: %s", address(verifier));
    }
}
