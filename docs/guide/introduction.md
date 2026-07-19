# Introduction

EthBFT is a thin BFT consensus adapter for Ethereum Execution Layer clients.
CometBFT decides complete Ethereum execution payloads, and every validator asks
an independent Geth node to validate the same state transition.

> **Status:** v0.1.0 MVP. The default Docker network has one validator. The
> protocol path is designed for one dedicated EL per CometBFT validator, but the
> project is not yet a production multi-validator network.

## Current protocol

- The proposer builds an Engine API V2 execution payload in `PrepareProposal`.
- A canonical RLP envelope and the exact ordered payload transactions become
  the CometBFT proposal.
- Validators reconstruct the payload and require `engine_newPayloadV2` to
  return `VALID` in `ProcessProposal`.
- Only after CometBFT decides the proposal does EthBFT advance canonical EL
  forkchoice.
- The ABCI app hash commits to the EL block hash, state root, receipts root, and
  transaction root.
- `Commit` persists the CometBFT height to EL block mapping with an fsynced
  atomic state update.

## MVP boundary

Protocol v1 supports a Shanghai-only private execution chain, Engine API V2,
empty withdrawals, and non-blob Ethereum transactions. State sync, dynamic
validators, mixed execution clients, and external light-client proofs remain
future work.

See [RFC 0001](/rfc/0001-execution-payload-consensus) for the complete target
protocol and security model.
