// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {Test} from "forge-std/Test.sol";
import {Merkle} from "murky/src/Merkle.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

import {Keystore} from "../../src/core/Keystore.sol";
import {IKeystore} from "../../src/interface/IKeystore.sol";
import {IVerifier} from "../../src/interface/IVerifier.sol";
import {UpdateAction, ValidateAction} from "../../src/lib/Actions.sol";

contract KeystoreTest is Test {
    Keystore public keystore;
    Merkle public ucmt;

    struct UpdateInputs {
        bytes32 root;
        bytes32[] proof;
        bytes node;
        uint256 nonce;
        bytes32 message;
    }

    function setUp() public {
        keystore = new Keystore();
        ucmt = new Merkle();
    }

    function testFuzz_initRootHash(bytes32 refHash, address account) public view {
        assertEq(keystore.getRootHash(refHash, account), refHash);
    }

    function testFuzz_initNonce(bytes32 refHash, address account, uint192 key) public view {
        assertEq(keystore.getNonce(refHash, account, key), 0 | uint256(key) << 64);
    }

    function testFuzz_validate(
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes32 message,
        bytes calldata data,
        uint256 validationData
    ) public {
        vm.assume(nodeVerifier != address(0));
        (bytes32 root, bytes32[] memory proof, bytes memory node) =
            _packNodeAndGenerateUCMT(nodes, index, nodeVerifier, nodeConfig);

        vm.mockCall(
            nodeVerifier,
            abi.encodeWithSelector(IVerifier.validateData.selector, message, data, nodeConfig),
            abi.encodePacked(validationData)
        );

        ValidateAction memory action =
            ValidateAction({refHash: root, message: message, proof: proof, node: node, data: data});
        assertEq(keystore.validate(action), validationData);
    }

    function testFuzz_validateInvalidProof(
        bytes32 badRoot,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes32 message,
        bytes calldata data
    ) public {
        vm.assume(nodeVerifier != address(0));
        (, bytes32[] memory proof, bytes memory node) = _packNodeAndGenerateUCMT(nodes, index, nodeVerifier, nodeConfig);

        ValidateAction memory action =
            ValidateAction({refHash: badRoot, message: message, proof: proof, node: node, data: data});
        vm.expectRevert(IKeystore.InvalidProof.selector);
        keystore.validate(action);
    }

    function testFuzz_validateInvalidNode(
        bytes32[] calldata nodes,
        uint256 index,
        bytes calldata node,
        bytes32 message,
        bytes calldata data
    ) public {
        vm.assume(node.length < 20);
        (bytes32 root, bytes32[] memory proof) = _generateUCMT(nodes, index, node);

        ValidateAction memory action =
            ValidateAction({refHash: root, message: message, proof: proof, node: node, data: data});
        vm.expectRevert(IKeystore.InvalidNode.selector);
        keystore.validate(action);
    }

    function testFuzz_validateInvalidVerifier(
        bytes32[] calldata nodes,
        uint256 index,
        bytes calldata nodeConfig,
        bytes32 message,
        bytes calldata data
    ) public {
        address badVerifier = address(0);
        (bytes32 root, bytes32[] memory proof, bytes memory node) =
            _packNodeAndGenerateUCMT(nodes, index, badVerifier, nodeConfig);

        ValidateAction memory action =
            ValidateAction({refHash: root, message: message, proof: proof, node: node, data: data});
        vm.expectRevert(IKeystore.InvalidVerifier.selector);
        keystore.validate(action);
    }

    function testFuzz_handleUpdates(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes calldata data
    ) public {
        vm.assume(nodeVerifier != address(0));
        UpdateInputs memory inputs =
            _packNodeAndGetUpdateInputs(nextHash, nonceKey, nodes, index, nodeVerifier, nodeConfig);

        vm.mockCall(
            nodeVerifier,
            abi.encodeWithSelector(IVerifier.validateData.selector, inputs.message, data, nodeConfig),
            abi.encodePacked(SIG_VALIDATION_SUCCESS)
        );
        vm.expectEmit();
        emit IKeystore.RootHashUpdated(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data, true);
        keystore.handleUpdates(_getUpdateActions(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data));

        bytes32 expectedRootHash = nextHash == bytes32(0) ? inputs.root : nextHash;
        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 1 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), expectedRootHash);
    }

    function testFuzz_handleUpdatesInvalidNonce(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes calldata data
    ) public {
        vm.assume(nodeVerifier != address(0));
        UpdateInputs memory inputs =
            _packNodeAndGetUpdateInputs(nextHash, nonceKey, nodes, index, nodeVerifier, nodeConfig);

        vm.expectRevert(IKeystore.InvalidNonce.selector);
        keystore.handleUpdates(
            _getUpdateActions(inputs.root, nextHash, inputs.nonce + 1, inputs.proof, inputs.node, data)
        );

        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 0 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), inputs.root);
    }

    function testFuzz_handleUpdatesInvalidProof(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes calldata data
    ) public {
        vm.assume(nodeVerifier != address(0));
        UpdateInputs memory inputs =
            _packNodeAndGetUpdateInputs(nextHash, nonceKey, nodes, index, nodeVerifier, nodeConfig);

        inputs.proof[inputs.proof.length - 1] = bytes32("0xdead");
        vm.expectRevert(IKeystore.InvalidProof.selector);
        keystore.handleUpdates(_getUpdateActions(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data));

        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 0 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), inputs.root);
    }

    function testFuzz_handleUpdatesInvalidNode(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        bytes calldata node,
        bytes calldata data
    ) public {
        vm.assume(node.length < 20);
        UpdateInputs memory inputs = _getUpdateInputs(nextHash, nonceKey, nodes, index, node);

        vm.expectRevert(IKeystore.InvalidNode.selector);
        keystore.handleUpdates(_getUpdateActions(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data));

        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 0 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), inputs.root);
    }

    function testFuzz_handleUpdatesInvalidVerifier(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        bytes calldata nodeConfig,
        bytes calldata data
    ) public {
        UpdateInputs memory inputs =
            _packNodeAndGetUpdateInputs(nextHash, nonceKey, nodes, index, address(0), nodeConfig);

        vm.expectRevert(IKeystore.InvalidVerifier.selector);
        keystore.handleUpdates(_getUpdateActions(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data));

        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 0 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), inputs.root);
    }

    function testFuzz_handleUpdatesInvalidValidation(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig,
        bytes calldata data
    ) public {
        vm.assume(nodeVerifier != address(0));
        UpdateInputs memory inputs =
            _packNodeAndGetUpdateInputs(nextHash, nonceKey, nodes, index, nodeVerifier, nodeConfig);

        vm.mockCall(
            nodeVerifier,
            abi.encodeWithSelector(IVerifier.validateData.selector, inputs.message, data, nodeConfig),
            abi.encodePacked(SIG_VALIDATION_FAILED)
        );
        vm.expectEmit();
        emit IKeystore.RootHashUpdated(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data, false);
        keystore.handleUpdates(_getUpdateActions(inputs.root, nextHash, inputs.nonce, inputs.proof, inputs.node, data));

        assertEq(keystore.getNonce(inputs.root, address(this), nonceKey), 0 | uint256(nonceKey) << 64);
        assertEq(keystore.getRootHash(inputs.root, address(this)), inputs.root);
    }

    function testFuzz_handleUpdatesBatch(bool[2] calldata status) public {
        UpdateAction[] memory actions = new UpdateAction[](2);

        actions[0] = UpdateAction({
            refHash: 0x0bea790c2d4a69970ebd6e09562a71084e5c78fef4d37528dd332cfb538542ce,
            nextHash: 0x307e09be09995e6faec1ee7e926814704ea5350149e0c43d3c33d08107993edd,
            nonce: 21345602813603236902997277615363180973908434092032,
            account: address(this),
            proof: new bytes32[](4),
            node: hex"367bbe350864b020ff1b8b7e418a815c2a947f9d09eadce97d0c9c596ac47be1bcc4e0bf1582b3fb3cb5ea2acb22f8c2bc170f7479c2",
            data: hex"81cd7f87ae22c33efc08d02b0374fe09023334940745167021c9e66dc920557be866a02a2255351258770f722394e90644d8a14f06"
        });
        actions[0].proof[0] = 0xf0720b5a99da88909ea1349c9fadbc47a3dadb16815b68532caa1090fa3cc7c3;
        actions[0].proof[1] = 0x1a9a5662b9f192a00b13ff9e28bfbc0594ad79a32760d4f5a2ee007c3bfa5140;
        actions[0].proof[2] = 0xa0ba7f0cac2c1a8c549a6618333bbe1fc53c029126d1ae6c3c6002b3b4ba6524;
        actions[0].proof[3] = 0x7a7f6bcecc35cccf14046a8016f81fb7a8ffee0d421195e67493fc7de1559744;

        actions[1] = UpdateAction({
            refHash: 0x919c2e64fdfe95a09781da7a31cec323904edeece2aadab9db2809401f24feb1,
            nextHash: 0xf5856318a232ea9e7991756d7ed9f32e6128c84bfefee127f06bc23fd22c0296,
            nonce: 779254045811195516568393371847926550426994733077148739871778103143432192,
            account: address(this),
            proof: new bytes32[](5),
            node: hex"217c31512a2fc94b172b5ef447d1deca0abf0c34a47ae671572752b2eafbb25ce40f59229f25811cfae1c253226d6b08cbecfd13e8b413cdbe616886c94b",
            data: hex"7b41359034736ce7bb5277e09979f3b337"
        });
        actions[1].proof[0] = 0xd75925ab1c24fe4af10b28baa7b632d28a52ffc73eae1a386152fd44e805fe15;
        actions[1].proof[1] = 0xbfc020b001604c83cdaf1759486f5d4547d89278b8e90ee2e49cc9b8576cf3ee;
        actions[1].proof[2] = 0xecd6bb55e8f496defad7865a73041e22a4a761938c6638e288e8380768e99c19;
        actions[1].proof[3] = 0xf8a598929a6ff9a031bc9727bf8536a590d1dc764fe678d5595f8459221a8e25;
        actions[1].proof[4] = 0xb0cf634098ce6f594f969fdde6243f10810a5a2817676821356a9aba230baf01;

        vm.mockCall(
            address(bytes20(actions[0].node)),
            abi.encodeWithSelector(
                IVerifier.validateData.selector,
                keccak256(
                    abi.encode(
                        actions[0].refHash,
                        actions[0].nextHash,
                        address(this),
                        actions[0].nonce,
                        keccak256(actions[0].node)
                    )
                ),
                actions[0].data,
                LibBytes.slice(actions[0].node, 20, actions[0].node.length)
            ),
            abi.encodePacked(status[0] ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED)
        );

        vm.mockCall(
            address(bytes20(actions[1].node)),
            abi.encodeWithSelector(
                IVerifier.validateData.selector,
                keccak256(
                    abi.encode(
                        actions[1].refHash,
                        actions[1].nextHash,
                        address(this),
                        actions[1].nonce,
                        keccak256(actions[1].node)
                    )
                ),
                actions[1].data,
                LibBytes.slice(actions[1].node, 20, actions[1].node.length)
            ),
            abi.encodePacked(status[1] ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED)
        );

        vm.expectEmit();
        emit IKeystore.RootHashUpdated(
            actions[0].refHash,
            actions[0].nextHash,
            actions[0].nonce,
            actions[0].proof,
            actions[0].node,
            actions[0].data,
            status[0]
        );

        vm.expectEmit();
        emit IKeystore.RootHashUpdated(
            actions[1].refHash,
            actions[1].nextHash,
            actions[1].nonce,
            actions[1].proof,
            actions[1].node,
            actions[1].data,
            status[1]
        );
        keystore.handleUpdates(actions);

        uint192 nonceKey0 = uint192(actions[0].nonce >> 64);
        uint192 nonceKey1 = uint192(actions[1].nonce >> 64);
        bytes32 currHash0 = status[0] ? actions[0].nextHash : actions[0].refHash;
        bytes32 currHash1 = status[1] ? actions[1].nextHash : actions[1].refHash;
        uint64 nonceSeq0 = status[0] ? 1 : 0;
        uint64 nonceSeq1 = status[1] ? 1 : 0;
        assertEq(keystore.getRootHash(actions[0].refHash, address(this)), currHash0);
        assertEq(keystore.getNonce(actions[0].refHash, address(this), nonceKey0), nonceSeq0 | uint256(nonceKey0) << 64);
        assertEq(keystore.getRootHash(actions[1].refHash, address(this)), currHash1);
        assertEq(keystore.getNonce(actions[1].refHash, address(this), nonceKey1), nonceSeq1 | uint256(nonceKey1) << 64);
    }

    // ================================================================
    // Helper functions
    // ================================================================

    function _packNodeAndGenerateUCMT(
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig
    ) internal view returns (bytes32 root, bytes32[] memory proof, bytes memory node) {
        vm.assume(nodes.length > 1);
        vm.assume(index < nodes.length);

        bytes32[] memory tree = nodes;
        node = abi.encodePacked(nodeVerifier, nodeConfig);
        tree[index] = keccak256(node);
        root = ucmt.getRoot(tree);
        proof = ucmt.getProof(tree, index);
    }

    function _generateUCMT(bytes32[] calldata nodes, uint256 index, bytes calldata node)
        internal
        view
        returns (bytes32 root, bytes32[] memory proof)
    {
        vm.assume(nodes.length > 1);
        vm.assume(index < nodes.length);

        bytes32[] memory tree = nodes;
        tree[index] = keccak256(node);
        root = ucmt.getRoot(tree);
        proof = ucmt.getProof(tree, index);
    }

    function _packNodeAndGetUpdateInputs(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        address nodeVerifier,
        bytes calldata nodeConfig
    ) internal view returns (UpdateInputs memory updateInputs) {
        (bytes32 root, bytes32[] memory proof, bytes memory node) =
            _packNodeAndGenerateUCMT(nodes, index, nodeVerifier, nodeConfig);

        updateInputs.root = root;
        updateInputs.proof = proof;
        updateInputs.node = node;
        updateInputs.nonce = keystore.getNonce(root, address(this), nonceKey);
        updateInputs.message = keccak256(abi.encode(root, nextHash, address(this), updateInputs.nonce, keccak256(node)));
    }

    function _getUpdateInputs(
        bytes32 nextHash,
        uint192 nonceKey,
        bytes32[] calldata nodes,
        uint256 index,
        bytes calldata node
    ) internal view returns (UpdateInputs memory updateInputs) {
        (bytes32 root, bytes32[] memory proof) = _generateUCMT(nodes, index, node);

        updateInputs.root = root;
        updateInputs.proof = proof;
        updateInputs.node = node;
        updateInputs.nonce = keystore.getNonce(root, address(this), nonceKey);
        updateInputs.message = keccak256(abi.encode(root, nextHash, address(this), updateInputs.nonce, keccak256(node)));
    }

    function _getUpdateActions(
        bytes32 refHash,
        bytes32 nextHash,
        uint256 nonce,
        bytes32[] memory proof,
        bytes memory node,
        bytes memory data
    ) internal view returns (UpdateAction[] memory) {
        UpdateAction[] memory actions = new UpdateAction[](1);
        UpdateAction memory action = UpdateAction({
            refHash: refHash,
            nextHash: nextHash,
            nonce: nonce,
            account: address(this),
            proof: proof,
            node: node,
            data: data
        });
        actions[0] = action;
        return actions;
    }
}
