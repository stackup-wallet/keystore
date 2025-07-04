// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {Test} from "forge-std/Test.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

import {Keystore} from "../../src/core/Keystore.sol";
import {IKeystore} from "../../src/interface/IKeystore.sol";
import {IVerifier} from "../../src/interface/IVerifier.sol";
import {UpdateAction, ValidateAction} from "../../src/lib/Actions.sol";

contract Keystore32NodeUCMT is Test {
    Keystore public keystore;

    function setUp() public {
        keystore = new Keystore();
    }

    function test_registerNode() public {
        bytes32[] memory proof = _getProof();
        ValidateAction memory action = _getValidateAction("");

        vm.startSnapshotGas("1. registerNode");
        keystore.registerNode(action.refHash, proof, action.node);
        vm.stopSnapshotGas();
    }

    function test_validate_withProof() public {
        bytes32[] memory proof = _getProof();
        ValidateAction memory action = _getValidateAction(abi.encode(proof));

        _mockVerifier(action.message, action.node, action.data);

        vm.startSnapshotGas("2. validate (with proof)");
        uint256 actualValidationData = keystore.validate(action);
        vm.stopSnapshotGas();
        assertEq(actualValidationData, SIG_VALIDATION_SUCCESS);
    }

    function test_validate_withoutProof() public {
        bytes32[] memory proof = _getProof();
        ValidateAction memory action = _getValidateAction("");
        keystore.registerNode(action.refHash, proof, action.node);

        _mockVerifier(action.message, action.node, action.data);

        action.node = abi.encode(keccak256(action.node));
        vm.startSnapshotGas("3. validate (without proof)");
        uint256 actualValidationData = keystore.validate(action);
        vm.stopSnapshotGas();
        assertEq(actualValidationData, SIG_VALIDATION_SUCCESS);
    }

    function test_handleUpdate_withProof() public {
        bytes32[] memory proof = _getProof();
        UpdateAction[] memory actions = _getUpdateActions(abi.encode(proof));

        _mockVerifier(
            keccak256(
                abi.encode(
                    actions[0].refHash,
                    actions[0].nextHash,
                    actions[0].account,
                    actions[0].nonce,
                    keccak256(actions[0].node)
                )
            ),
            actions[0].node,
            actions[0].data
        );

        vm.expectEmit();
        emit IKeystore.RootHashUpdated(
            actions[0].refHash,
            actions[0].nextHash,
            actions[0].nonce,
            actions[0].proof,
            actions[0].node,
            actions[0].data,
            true
        );
        vm.startSnapshotGas("4. handleUpdates (with proof)");
        keystore.handleUpdates(actions);
        vm.stopSnapshotGas();
    }

    function test_handleUpdate_withoutProof() public {
        bytes32[] memory proof = _getProof();
        UpdateAction[] memory actions = _getUpdateActions("");
        keystore.registerNode(actions[0].refHash, proof, actions[0].node);

        _mockVerifier(
            keccak256(
                abi.encode(
                    actions[0].refHash,
                    actions[0].nextHash,
                    actions[0].account,
                    actions[0].nonce,
                    keccak256(actions[0].node)
                )
            ),
            actions[0].node,
            actions[0].data
        );

        vm.expectEmit();
        emit IKeystore.RootHashUpdated(
            actions[0].refHash, actions[0].nextHash, actions[0].nonce, "", actions[0].node, actions[0].data, true
        );
        actions[0].node = abi.encode(keccak256(actions[0].node));
        vm.startSnapshotGas("5. handleUpdates (without proof)");
        keystore.handleUpdates(actions);
        vm.stopSnapshotGas();
    }

    // ================================================================
    // Helper functions
    // ================================================================

    function _getProof() internal pure returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](5);
        proof[0] = 0xd75925ab1c24fe4af10b28baa7b632d28a52ffc73eae1a386152fd44e805fe15;
        proof[1] = 0xbfc020b001604c83cdaf1759486f5d4547d89278b8e90ee2e49cc9b8576cf3ee;
        proof[2] = 0xecd6bb55e8f496defad7865a73041e22a4a761938c6638e288e8380768e99c19;
        proof[3] = 0xf8a598929a6ff9a031bc9727bf8536a590d1dc764fe678d5595f8459221a8e25;
        proof[4] = 0xb0cf634098ce6f594f969fdde6243f10810a5a2817676821356a9aba230baf01;
        return proof;
    }

    function _getValidateAction(bytes memory proof) internal pure returns (ValidateAction memory) {
        return ValidateAction({
            refHash: 0x919c2e64fdfe95a09781da7a31cec323904edeece2aadab9db2809401f24feb1,
            message: keccak256(hex"deadbeef"),
            proof: proof,
            node: hex"217c31512a2fc94b172b5ef447d1deca0abf0c34a47ae671572752b2eafbb25ce40f59229f25811cfae1c253226d6b08cbecfd13e8b413cdbe616886c94b",
            data: hex"7b41359034736ce7bb5277e09979f3b337"
        });
    }

    function _getUpdateActions(bytes memory proof) internal view returns (UpdateAction[] memory) {
        UpdateAction[] memory actions = new UpdateAction[](1);
        actions[0] = UpdateAction({
            refHash: 0x919c2e64fdfe95a09781da7a31cec323904edeece2aadab9db2809401f24feb1,
            nextHash: 0xf5856318a232ea9e7991756d7ed9f32e6128c84bfefee127f06bc23fd22c0296,
            nonce: 779254045811195516568393371847926550426994733077148739871778103143432192,
            account: address(this),
            proof: proof,
            node: hex"217c31512a2fc94b172b5ef447d1deca0abf0c34a47ae671572752b2eafbb25ce40f59229f25811cfae1c253226d6b08cbecfd13e8b413cdbe616886c94b",
            data: hex"7b41359034736ce7bb5277e09979f3b337"
        });
        return actions;
    }

    function _mockVerifier(bytes32 message, bytes memory node, bytes memory data) internal {
        vm.mockCall(
            address(bytes20(node)),
            abi.encodeWithSelector(
                IVerifier.validateData.selector, message, data, LibBytes.slice(node, 20, node.length)
            ),
            abi.encodePacked(SIG_VALIDATION_SUCCESS)
        );
    }
}
