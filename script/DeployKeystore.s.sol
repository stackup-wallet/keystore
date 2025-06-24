// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {Keystore} from "src/core/Keystore.sol";

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        Keystore keystore = new Keystore{salt: 0}();
        vm.stopBroadcast();

        console.log("Deploying Keystore at: %s", address(keystore));
    }
}
