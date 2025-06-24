// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Script, console} from "forge-std/Script.sol";

import {KeystoreAccountFactory} from "src/account/KeystoreAccountFactory.sol";
import {IKeystore} from "src/interface/IKeystore.sol";

contract Deploy is Script {
    function run() public {
        IEntryPoint entryPoint = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
        IKeystore keystore = IKeystore(0x18c90BdFc5667D11605ebde82E5E9CDC4D789363);

        vm.startBroadcast();
        KeystoreAccountFactory factory = new KeystoreAccountFactory{salt: 0}(entryPoint, keystore);
        vm.stopBroadcast();

        console.log("Deploying KeystoreAccountFactory at: %s", address(factory));
    }
}
