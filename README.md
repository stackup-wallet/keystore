# Keystore

This repository provides a complete implementation of a Merkle tree Keystore, a supporting ERC-4337 account, and verifiers for common verification schemes.

**Refer to the [spec](./doc/spec.md) for a full deep dive into the implemented Keystore protocol.**

## Deployments

All contracts are deployed deterministically with the following addresses.

| Contract                     | Address                                      |
| ---------------------------- | -------------------------------------------- |
| Keystore                     | `0x18c90BdFc5667D11605ebde82E5E9CDC4D789363` |
| KeystoreAccountFactory       | `0x2F775F9FFC02231C3Bb1EA1281f1Da9ba2f2a069` |
| UserOpECDSAVerifier          | `0xf5bC4DB1cdedf1aDDD0d6543BA669837d5D0f3b3` |
| UserOpMultiSigVerifier       | `0xC498f1f881bdd8a2FEB6aABf166cF6E08Cf4e559` |
| UserOpWebAuthnVerifier       | `0xEcb9be3dbB737Ed13a768B2B7D030B483Bf5c9f2` |
| UserOpWebAuthnCosignVerifier | `0x36674817e050a37DA325d66B6dbD1a93063Dc6B9` |

## Usage

Before being able to run any command, you need to create a .env file and set your environment variables. You can follow the example in .env.example.

### Install dependencies

```shell
$ forge install
```

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Deploy

```shell
# Keystore
source .env && forge script script/DeployKeystore.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast

# Keystore account factory
source .env && forge script script/DeployKeystoreAccountFactory.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast

# Verifiers
source .env && forge script script/DeployUserOpECDSAVerifier.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpMultiSigVerifier.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpWebAuthnVerifier.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpWebAuthnCosignVerifier.s.sol --rpc-url $BASE_RPC_URL --ledger --verify --broadcast
```
