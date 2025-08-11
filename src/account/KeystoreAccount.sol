// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TokenCallbackHandler} from "account-abstraction/accounts/callback/TokenCallbackHandler.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC1271} from "solady/accounts/ERC1271.sol";
import {Initializable} from "solady/utils/Initializable.sol";

import {IKeystore} from "../interface/IKeystore.sol";
import {ValidateAction} from "../lib/Actions.sol";
import {KeystoreUserOperation} from "../lib/KeystoreUserOperation.sol";

contract KeystoreAccount is BaseAccount, TokenCallbackHandler, ERC1271, Initializable {
    error ERC1271SignerUnused();

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
            action.node = bytes.concat(keccak256(action.node)); // convert from bytes32 to bytes
        }

        return IKeystore(_keystore).validate(action);
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

    // ================================================================
    // Internal functions
    // ================================================================

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "KeystoreAccount";
        version = "1";
    }

    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool)
    {
        (bytes memory proof, bytes memory node, bytes memory data) = abi.decode(signature, (bytes, bytes, bytes));
        ValidateAction memory action =
            ValidateAction({refHash: refHash, message: hash, proof: proof, node: node, data: data});
        return IKeystore(_keystore).validate(action) != SIG_VALIDATION_FAILED;
    }

    /**
     * @dev This override is required by the ERC1271 inheritance but will NEVER
     * be called. Signature validation is always handled by the Keystore contract
     * via the _erc1271IsValidSignatureNowCalldata override and never through a
     * signer address check as seen in the abstract implementation.
     */
    function _erc1271Signer() internal pure override returns (address) {
        revert ERC1271SignerUnused();
    }
}
