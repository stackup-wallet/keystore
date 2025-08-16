# Keystore

This repository provides a complete implementation of a Merkle tree Keystore, a supporting ERC-4337 account, and verifiers for common verification schemes.

**Refer to the [spec](./doc/spec.md) for a full deep dive into the implemented Keystore protocol.**

## Deployments

All contracts are deployed deterministically with the following addresses.

| Contract                     | Address                                      |
| ---------------------------- | -------------------------------------------- |
| Keystore                     | `0x69C9F626b5Bd934C0F9806346682eD407FB978d3` |
| KeystoreAccountFactory       | `0x625cF8EDec3f68d48D3aA385F356524B04760BE8` |
| UserOpECDSAVerifier          | `0x294CD71960eed5AEa11DbbFa5D3c8eA4A1c1CE0F` |
| UserOpMultiSigVerifier       | `0x1dBadE1E34706f83598ae9acFC63B7F4f928146E` |
| UserOpWebAuthnVerifier       | `0xE19620169A26aEbC4Fe229A073639da6b009bF1a` |
| UserOpWebAuthnCosignVerifier | `0x7CD0D83C0c33AAC9cef88c75F3EDec80F4175252` |

## Usage

Before being able to run any command, you need to create a .env file and set your environment variables. You can follow the example in .env.example.

### Install dependencies

```shell
$ forge install
$ npm install
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
source .env && forge script script/DeployKeystore.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast

# Keystore account factory
source .env && forge script script/DeployKeystoreAccountFactory.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast

# Verifiers
source .env && forge script script/DeployUserOpECDSAVerifier.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpMultiSigVerifier.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpWebAuthnVerifier.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast
source .env && forge script script/DeployUserOpWebAuthnCosignVerifier.s.sol --rpc-url $ETH_RPC_URL --ledger --verify --broadcast
```

### Example scripts

The following commands are useful for users and application developers to work with the Keystore protocol.

#### Verify configuration

A minimal script to generate and verify a UCMT using the [openzeppelin Merkle tree library](https://github.com/OpenZeppelin/merkle-tree).

```shell
$ npm run examples:verify-ucmt
```
