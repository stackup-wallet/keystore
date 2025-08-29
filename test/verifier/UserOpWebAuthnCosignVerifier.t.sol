// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/console.sol";

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";
import {Base64} from "solady/utils/Base64.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibString} from "solady/utils/LibString.sol";
import {P256} from "solady/utils/P256.sol";
import {WebAuthn} from "solady/utils/WebAuthn.sol";

import {OnlyKeystore} from "../../src/lib/OnlyKeystore.sol";
import {UserOpWebAuthnCosignVerifier} from "../../src/verifier/UserOpWebAuthnCosignVerifier.sol";

contract UserOpWebAuthnCosignVerifierTest is Test {
    using LibString for string;

    struct P256Key {
        bytes32 pk;
        bytes32 x;
        bytes32 y;
    }

    UserOpWebAuthnCosignVerifier public verifier;

    bytes constant authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a";
    string constant clientDataJSONPre = '{"type":"webauthn.get","challenge":"';
    string constant clientDataJSONPost = '","origin":"http://localhost:3005","crossOrigin":false}';
    uint256 constant challengeIndex = 23;
    uint256 constant typeIndex = 1;

    function setUp() public {
        verifier = new UserOpWebAuthnCosignVerifier(address(this));
        _etchP256Verifier();
    }

    function testFuzz_validateData(bool withUserOp, uint256 index) public {
        (address cosigner, uint256 cosignerPK) = makeAddrAndKey("cosigner");
        P256Key memory signer = _getSigner(index);
        bytes32 message = keccak256("Signed by signer");
        bytes memory signature = _webAuthnCosign(cosignerPK, uint256(signer.pk), message);

        bytes memory data = signature;
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = signature;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        uint256 validationData = verifier.validateData(message, data, abi.encode(cosigner, signer.x, signer.y));
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function testFuzz_validateDataValidationFailedWebAuthn(bool withUserOp, uint256 index, bytes32 x, bytes32 y)
        public
    {
        (address cosigner, uint256 cosignerPK) = makeAddrAndKey("cosigner");
        P256Key memory signer = _getSigner(index);
        bytes32 message = keccak256("Signed by signer");
        bytes memory signature = _webAuthnCosign(cosignerPK, uint256(signer.pk), message);

        bytes memory data = signature;
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = signature;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        uint256 validationData = verifier.validateData(message, data, abi.encode(cosigner, x, y));
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testFuzz_validateDataValidationFailedCosign(bool withUserOp, uint256 index, address cosigner) public {
        (, uint256 cosignerPK) = makeAddrAndKey("cosigner");
        P256Key memory signer = _getSigner(index);
        bytes32 message = keccak256("Signed by signer");
        bytes memory signature = _webAuthnCosign(cosignerPK, uint256(signer.pk), message);

        bytes memory data = signature;
        if (withUserOp) {
            PackedUserOperation memory userOp;
            userOp.signature = signature;
            data = abi.encode(userOp);
        } else {
            data = abi.encodePacked(verifier.SIGNATURES_ONLY_TAG(), data);
        }

        uint256 validationData = verifier.validateData(message, data, abi.encode(cosigner, signer.x, signer.y));
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testFuzz_validateDataInvalidCaller(address keystore) public {
        vm.assume(keystore != address(this));
        vm.prank(keystore);
        vm.expectRevert(OnlyKeystore.NotFromKeystore.selector);
        verifier.validateData(0, "", "");
    }

    function testFuzz_validateDataInvalidData(bytes calldata data) public {
        vm.expectRevert();
        verifier.validateData(0, data, "");
    }

    // ================================================================
    // Helper functions
    // ================================================================

    function _webAuthnCosign(uint256 cosignerPrivateKey, uint256 privateKey, bytes32 message)
        internal
        pure
        returns (bytes memory signature)
    {
        (uint8 cosignerV, bytes32 cosignerR, bytes32 cosignerS) =
            vm.sign(cosignerPrivateKey, ECDSA.toEthSignedMessageHash(message));

        string memory clientDataJSON =
            clientDataJSONPre.concat(Base64.encode(abi.encode(message), true, true)).concat(clientDataJSONPost);
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, clientDataJSONHash));
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, messageHash);
        if (uint256(s) > P256.N / 2) {
            s = bytes32(P256.N - uint256(s));
        }

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: r,
            s: s
        });
        signature = abi.encode(abi.encodePacked(cosignerR, cosignerS, cosignerV), WebAuthn.encodeAuth(auth));
    }

    function _etchP256Verifier() internal {
        // See https://gist.github.com/Vectorized/599b0d8a94d21bc74700eb1354e2f55c
        // This can be removed once foundry has P256 precompile
        vm.etch(
            0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a,
            hex"3d604052610216565b60008060006ffffffffeffffffffffffffffffffffff60601b19808687098188890982838389096004098384858485093d510985868b8c096003090891508384828308850385848509089650838485858609600809850385868a880385088509089550505050808188880960020991505093509350939050565b81513d83015160408401516ffffffffeffffffffffffffffffffffff60601b19808384098183840982838388096004098384858485093d510985868a8b096003090896508384828308850385898a09089150610102848587890960020985868787880960080987038788878a0387088c0908848b523d8b015260408a0152565b505050505050505050565b81513d830151604084015185513d87015160408801518361013d578287523d870182905260408701819052610102565b80610157578587523d870185905260408701849052610102565b6ffffffffeffffffffffffffffffffffff60601b19808586098183840982818a099850828385830989099750508188830383838809089450818783038384898509870908935050826101be57836101be576101b28a89610082565b50505050505050505050565b808485098181860982828a09985082838a8b0884038483860386898a09080891506102088384868a0988098485848c09860386878789038f088a0908848d523d8d015260408c0152565b505050505050505050505050565b6020357fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325513d6040357f7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a88111156102695782035b60206108005260206108205260206108405280610860526002830361088052826108a0526ffffffffeffffffffffffffffffffffff60601b198060031860205260603560803560203d60c061080060055afa60203d1416837f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8585873d5189898a09080908848384091484831085851016888710871510898b108b151016609f3611161616166103195760206080f35b60809182523d820152600160c08190527f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966102009081527f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f53d909101526102405261038992509050610100610082565b610397610200610400610082565b6103a7610100608061018061010d565b6103b7610200608061028061010d565b6103c861020061010061030061010d565b6103d961020061018061038061010d565b6103e9610400608061048061010d565b6103fa61040061010061050061010d565b61040b61040061018061058061010d565b61041c61040061020061060061010d565b61042c610600608061068061010d565b61043d61060061010061070061010d565b61044e61060061018061078061010d565b81815182350982825185098283846ffffffffeffffffffffffffffffffffff60601b193d515b82156105245781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f71c16610600888a1b60f51c16176040810151801585151715610564578061055357506105fe565b81513d8301519750955093506105fe565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a015109089350836105b957806105b9576105a9898c8c610008565b9a509b50995050505050506105fe565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b5082156106af5781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f51c16610600888a1b60f31c161760408101518015851517156106ef57806106de5750610789565b81513d830151975095509350610789565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a01510908935083610744578061074457610734898c8c610008565b9a509b5099505050505050610789565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b50600488019760fb19016104745750816107a2573d6040f35b81610860526002810361088052806108a0523d3d60c061080060055afa898983843d513d510987090614163d525050505050505050503d3df3fea264697066735822122063ce32ec0e56e7893a1f6101795ce2e38aca14dd12adb703c71fe3bee27da71e64736f6c634300081a0033"
        );
    }

    function _getSigner(uint256 index) internal pure returns (P256Key memory) {
        P256Key[] memory signers = new P256Key[](32);
        signers[0] = P256Key({
            pk: 0x802f9aefe430c634cf88f24fa512fbcf9e09a2773d5afa828aa13dfce3fdbb79,
            x: 0x8a33036bf1a24f56d51df76fef1605b291976b86a3af0b62a0668aa51937c0d7,
            y: 0xd309ff0cd93f8f003d363b09c7fa67f71bf5698ceb4b608625b610cb68d9e9e0
        });
        signers[1] = P256Key({
            pk: 0x0ec98b399e00801ce5a6648305b3653b1d324be1cc9db76260d117d933b45ca0,
            x: 0xd94c731dd2c87a3ef59d7e57ec3fd0edff14f8becd5c2e3e3cc2738945ac22e3,
            y: 0x8e2feb1a1905cb5c76771dbf221917aaca0d90e46ed5d698e797070470842909
        });
        signers[2] = P256Key({
            pk: 0x7cb80a0f47d175d447f700f6e2e9ea70e890e2aadccacab936c0578ec838a562,
            x: 0xd5c1f8eb0c160f849ae4702ecd978d89fc87abf79365b3535c085559504875c7,
            y: 0xa585226d58d9f82fa9ee94be22a45e81293fe318bad596bf903be5410d3f6b51
        });
        signers[3] = P256Key({
            pk: 0xe7589038003dd3e8ead5926c6ef5f1c2d73c40ab29aaee2341f7004c31f49389,
            x: 0x3347da2c3b6a4d90d0597d7ab49d77fc3084bd390b11646fb1fe79a81d540ca4,
            y: 0x6fff4b96b45cd5f3dda13c788de3b7660fa695d45a028ad485c19dc6a1dea16c
        });
        signers[4] = P256Key({
            pk: 0x9babbff84b873bdd9f20cc6a100ffbb02ad21a6470fb6bc2f2c2cfc7f824d4a4,
            x: 0xa575b7efe94661d9d49f029bd8b72815001ca0ffd8622b5853731093c757bcca,
            y: 0x4e06caabe77a02a671f4a6d8890728583ec19560936dc6b0fb63414b84cb6eec
        });
        signers[5] = P256Key({
            pk: 0x5e13274e97354deae368f4900cbc02facfa9ad4afaf3a922c947b2fd44a6b9bb,
            x: 0x2b9532de0ba2c4a6e319c73a77bdaf87e707f8eba01618cdfa7e5bc000478f94,
            y: 0x00bec9cb854af57343f7aafa0a132efc5730d44b3983cd5fd9ce670fbdac7871
        });
        signers[6] = P256Key({
            pk: 0xe0f13523a046d3676b720a8b6444c8199888a8c78013621c1e3e2d74532109ed,
            x: 0xc6c12930ddd65e523a866e9a99477e82aa725bc06b760b01ee2dc6d9e0dff769,
            y: 0x452d2631c47d247fd14d7a40bec306adde1a3b7ff110f9dde937103201c0bf50
        });
        signers[7] = P256Key({
            pk: 0x41d86da9e2c44b67b53c96af18746d30738dfa4fab27657727a9e4c4949f6319,
            x: 0x0ffec4558285b3b69b92dbbb54013af8737a99ff70086fa2ffc373dfbbca988d,
            y: 0x03c3f319a70578e228b150bb1687ac20f094b692626c182a843ff43fdf434b52
        });
        signers[8] = P256Key({
            pk: 0x29b838beebc436e537fb3d8a24c64bf17bbf558f6946cf82e24956a6a0453d21,
            x: 0xba08165a9157fd3cfeee53c7a636522d96ea14b61ad0575f2d566560d50eaac2,
            y: 0x34efbb1014bea27b133576fb4e819dc2a6dd895d0722b71c607155981559945d
        });
        signers[9] = P256Key({
            pk: 0xdd5e60c654889f0609ece2b30c863b77d74e09bcbddc688801bc698ff5496f6c,
            x: 0xe4839a9e7977f03ce01d99502513b4d80d9bd5187549339de93acb37840e1367,
            y: 0xa19c4d6e78943f28a31481d6dc2062a77912d62eead6c7e649334688e05fcc71
        });
        signers[10] = P256Key({
            pk: 0x7a5339ab2d9839e456648a14fb11c87743bdd1ac8a7d75b30051bb72c768936a,
            x: 0x0ef1a10392ed300abb0eccbe328d4c1ca14ffad274120fb1f3eaa6997e242e44,
            y: 0x658ba821af3b5f7274b355eceda94e35a72dd95a65a7660039c20c90fa493174
        });
        signers[11] = P256Key({
            pk: 0x2e5756fe654249c46b7316f9e6bbd63510bb02e669a9baa528f76624d0f8cd54,
            x: 0x72b3e2fdd6e7114e8e66d63db8630b0533b8f0bc8dfb31791338b8ed603195a4,
            y: 0x9f7bc6dbeaa0c689894c51408559b3deb2f149d638193745115f3dfde517b85d
        });
        signers[12] = P256Key({
            pk: 0xf2cc44d051cc9c3d2853428c5fe1efae7578164b51ea71d6364d83361a3cf945,
            x: 0x985ee201fca5a1c3bf7baedb769dcb0f7f7e2c9200c52c32be1fedca54229033,
            y: 0xc95d45cc2f2542ae6d9d1c20f38aaa9c82458638c9ec3230a331d158a12d2889
        });
        signers[13] = P256Key({
            pk: 0xad58ea0e8a30e937a0fb0ea2d5eea4aa7df6dfb9c811168a30d70c8ee0507d32,
            x: 0x50c0880f625891d312d4c1207c3573b829f5d6863be293c5365af7c1be23b5c3,
            y: 0xc2a87852b5b69561a7596315db342b15c65cff212b9c67d3baf86842fc9f4bde
        });
        signers[14] = P256Key({
            pk: 0x32f64c68e692e738f44124a62a5abb9ceee1b37bad3698205fbec2226d0db559,
            x: 0x2f49a4dfbead09aa7f7e198c1dc7d5cb4539b0a1a94181166654c84e5c92272a,
            y: 0xb008147e65ce42fca864ddfc76e1e2d0e945d04781eb8f4c575070ba7aa2038b
        });
        signers[15] = P256Key({
            pk: 0x469e5005b34d713e520196b2d0c05556a0ffd5b5f058f8b014dad41ebbf97a2d,
            x: 0xe414e89bb8b3772a6b44ad8c1591ed192b99cbd29200e5479220907078c9f7f9,
            y: 0xcddc26d2259cf29bae0687d95318886a0a5721aaa3e8c6a30359d76ed2f038b8
        });
        signers[16] = P256Key({
            pk: 0x978125609f3ef9e742abd4dba8d8e5e9329ff0840ee8655f25b20680454c4fb8,
            x: 0xa81ed6e11598bdecb4fb8b810b5c866db1f694a1ec8f62f000e909dad25d0d2c,
            y: 0xb7c78fafdff8ad8baf551d0cd0d2008d6afc239e498556e186c2e07caea06839
        });
        signers[17] = P256Key({
            pk: 0xe7994a1d9448df138a29c72b6cc4070c11624403a89b8daa7f3a2f095840a254,
            x: 0x3c47b3262cf94accbd533e548082bab8eab5e02d16f9edcaa957ab211c6cc7ca,
            y: 0xf4d4dd0dc762e54746bacd5df0fea59575d5ae10f23270388f0afde19a420cc5
        });
        signers[18] = P256Key({
            pk: 0x5fed243964f0638d044830ce77789db3af21706392d25a57b17bc5558c544691,
            x: 0xbc0e525ab6ae00f11b4edbb4d9a88447cd9242dd3cb18fe54725d742f3f88c74,
            y: 0x61e5385f70c1c5533647b43c635e41259d41fb8bfa35747edd3ab1590156700c
        });
        signers[19] = P256Key({
            pk: 0x52b91812290ee2361b1a8dbfd7c05b937c1a3283ed28920a478185eaaed439b1,
            x: 0x80db1dea4333930c76fe649d002e90979e0fd71098ed5f42e6b5b7241fa19297,
            y: 0x58eec7d904ec545c17a21d4d5f6ac9a7a56dedc653609c1685db1eec3e67b4fc
        });
        signers[20] = P256Key({
            pk: 0x24402d0f69ca9b36b795a6e055a077729807df16ad71b58aaf35ffe8f63f1cc1,
            x: 0x4711282940f9edfae26d29b19be2728ebe6332a0b770998ee0914c2c2b38f269,
            y: 0x630ac7a4c1d94406b1f7b44af0c2f1609f8bb8ef2efea14a6346b2c69a92d5f4
        });
        signers[21] = P256Key({
            pk: 0x37fc83f6d0cbafc21853acd670e033ed650ea8216f55764caa29cca088db75b4,
            x: 0xb341e902188c1a6b2bd19ac32cc029e0a7b7705e22b122f30d801ba50787b19c,
            y: 0xc9bda8a10f40a6aae56224e282d7f0ab6944fc8306563a8895649916cd5620f5
        });
        signers[22] = P256Key({
            pk: 0xf355b78e67aa18fc1fe081d22bde7e1894d38daf6633b1a90eb0662a7b5e5005,
            x: 0xaff34ecdc36486b4197cd21c40c15f5ff2c0c306dc6092b79bd849878651e74b,
            y: 0xc1ccd5a239dff8f259f99e0f13f77ac227623af75d3c8ac9e933b1cefdc55ad4
        });
        signers[23] = P256Key({
            pk: 0x08aeaccea50a9d9743e1ecd379044e29e39a761dd9c1b3e55c4db528aba07be4,
            x: 0xd5cbe9dcf30e1fc360bfa85f38b151493b4b185c60de3ae0c48da9a8f4f52a25,
            y: 0x29d543a3f61c59af90ee212d1eeee9344f04370ae739d46896a4b3e45a8df154
        });
        signers[24] = P256Key({
            pk: 0x28135ac8403cb70c4a1ff3a9b3a23c3b8f446b0c9d48f6901a7c84f90c34de64,
            x: 0xb8489a5ced699d9e1231743cfdfc79661cb70df73fd5d35ae506d75f064fc753,
            y: 0x8489e4b5d8d4d8f59d49f39873c64fb36eb52cb07865ab258d5f7f23a53987bb
        });
        signers[25] = P256Key({
            pk: 0xd7bedb4c51aa345ce970d045ad30a7b3ecbb506f5f8b86dd4798399179dbcef4,
            x: 0x03502081dead725a3f328dbfd368cfbae46002bb74167486347c4459d61aebcd,
            y: 0x69ebc2be7a57fdbf973c4055c8f212530c122237a5640128ee73d1837186c265
        });
        signers[26] = P256Key({
            pk: 0xd246eb1c04c7d5aac6fcc0e8b3cd55a52a2f275077cbdf73cc0a70d7722a2e91,
            x: 0x96f89d91e772a48cd7e2a02fbdf094e45a33c8e52fed943b1324aafa8b0b9017,
            y: 0xc8c02a162df6137a6f478f764b591457bc510cf1b39650372ce44240eecc2f46
        });
        signers[27] = P256Key({
            pk: 0xf9ff78898461267c6895c7a4085988c8c23c6f43c01da67042159058b417ca4b,
            x: 0x62a756fa42056164fef207a01c7d1e00cfea95947056fcb4196e8065878a8e29,
            y: 0xc646e1b24e6f45dfa69319533210f24b36a6dfc8c9f18560016fc76b6952b53a
        });
        signers[28] = P256Key({
            pk: 0xe1538946411d8b0dea216c39115f3e67ba122def581a8ba393c9277aa8b608e5,
            x: 0xeb25886d0a84908b3a4b80ccf5b1a5d6d26ee09b7216b91f5df45ba0224a7066,
            y: 0x60adb980d55a0ae5c06f5a8b7dedfc8bb44980d46fb7e03c189b1ce23313f43b
        });
        signers[29] = P256Key({
            pk: 0x91971e52db6ecf61c13c0bb0f7aa31a0b0d272413cda01318f6f17c6d9626f44,
            x: 0x1c23d5c0b2ba139dddfd9c25955375e02a7682fbba1649bf6ba11c8f1841d49b,
            y: 0x83f7dec36a354697e6d17808491ee72f436c6d93fec422a3e3f653a79e664e72
        });
        signers[30] = P256Key({
            pk: 0xd771403c39b504d09fa666f28a3e8884823504f89e0998f1c8b98060521d73e7,
            x: 0x01dd96e2eb3a439325fd9560a7bec67fa4e866690b4653221fddf8009deaab80,
            y: 0xa62e659cb61ca1536f107cce6ed41e071aab64b5702e2699a577dfebac0c0f80
        });
        signers[31] = P256Key({
            pk: 0x5e1832c267e5a2c94151a3c82dc7591eadba01e69faa97c8338bfa258dd44315,
            x: 0x2f6cc62f7dbad56247bb0ce924241b5215fa83a5883df05f2d24ba0c6e334544,
            y: 0xfc2589e72f51f0a81ed6ecb072b0821ee0fcadb210cdd39fc43c4dced732883a
        });
        vm.assume(index < signers.length);
        return signers[index];
    }
}
