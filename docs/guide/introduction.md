# Introduction

EthBFT is a small coordination layer between a BFT engine and an Ethereum
Execution Layer client. It does not implement the EVM, transaction networking,
or a second application database.

Protocol v2 sends user transactions directly to the EL. The proposer builds a
complete execution payload through Engine API; CometBFT decides that payload;
every validator independently requires `VALID` from its own EL before voting.

The current release is a pre-production alpha. Geth/Shanghai is the reference
integration and is exercised in single-validator and four-validator
fault-recovery CI. Other clients are candidates until their conformance
matrices are continuously green. See [Compatibility](/compatibility) and
[Production readiness](/production-readiness).
