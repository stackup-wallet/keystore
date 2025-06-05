# Keystore

This repository provides a complete implementation of a Merkle tree Keystore, a supporting ERC-4337 account, and verifiers for common verification schemes.

**Refer to the [spec](./doc/spec.md) for a full deep dive into the implemented Keystore protocol.**

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
$ source .env && forge script script/Deploy.s.sol:Deploy --rpc-url $RPC_URL --private-key $PRIVATE_KEY
```
