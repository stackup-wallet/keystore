// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {UserOpMultiSigVerifier} from "src/verifier/UserOpMultiSigVerifier.sol";

contract Deploy is Script {
    function run() public {
        address keystore = 0x69C9F626b5Bd934C0F9806346682eD407FB978d3;

        vm.startBroadcast();
        UserOpMultiSigVerifier verifier = new UserOpMultiSigVerifier{salt: 0}(keystore);
        vm.stopBroadcast();

        console.log("Deploying UserOpMultiSigVerifier at: %s", address(verifier));
    }
}
