// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {UserOpECDSAVerifier} from "src/verifier/UserOpECDSAVerifier.sol";

contract Deploy is Script {
    function run() public {
        address keystore = 0x69C9F626b5Bd934C0F9806346682eD407FB978d3;

        vm.startBroadcast();
        UserOpECDSAVerifier verifier = new UserOpECDSAVerifier{salt: 0}(keystore);
        vm.stopBroadcast();

        console.log("Deploying UserOpECDSAVerifier at: %s", address(verifier));
    }
}
