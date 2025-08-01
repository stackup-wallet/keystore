// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Initializable} from "solady/utils/Initializable.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {ValidateAction} from "../lib/Actions.sol";
import {ERC1271} from "../lib/ERC1271.sol";
import {KeystoreUserOperation} from "../lib/KeystoreUserOperation.sol";

contract KeystoreAccount is BaseAccount, ERC1271, Initializable {
    bytes32 public refHash;

    IEntryPoint private immutable _entryPoint;
    IKeystore private immutable _keystore;

    event KeystoreAccountInitialized(
        IEntryPoint indexed entryPoint, IKeystore indexed keystore, bytes32 indexed refHash
    );

    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    function keystore() public view returns (IKeystore) {
        return _keystore;
    }

    receive() external payable {}

    constructor(IEntryPoint anEntryPoint, IKeystore aKeystore) {
        _entryPoint = anEntryPoint;
        _keystore = aKeystore;
        _disableInitializers();
    }

    function initialize(bytes32 aRefHash) public virtual initializer {
        refHash = aRefHash;
        emit KeystoreAccountInitialized(_entryPoint, _keystore, refHash);
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        ValidateAction memory action = KeystoreUserOperation.prepareValidateAction(userOp, userOpHash, refHash);
        if (action.proof.length != 0) {
            IKeystore(_keystore).registerNode(refHash, abi.decode(action.proof, (bytes32[])), action.node);
            action.proof = "";
            action.node = abi.encode(keccak256(action.node));
        }

        return IKeystore(_keystore).validate(action);
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        public
        view
        virtual
        override
        returns (bytes4 magicValue)
    {
        (bytes memory proof, bytes memory node, bytes memory data) = abi.decode(signature, (bytes, bytes, bytes));
        ValidateAction memory action =
            ValidateAction({refHash: refHash, message: hash, proof: proof, node: node, data: data});
        if (IKeystore(_keystore).validate(action) == SIG_VALIDATION_FAILED) {
            return ERC1271_INVALID_VALUE;
        }
        return ERC1271_VALID_VALUE;
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public {
        _requireForExecute();
        entryPoint().withdrawTo(withdrawAddress, amount);
    }
}
