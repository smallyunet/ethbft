# Changelog

## v0.1.1 - 2026-07-20

### Fixed

- Explicitly make Docker E2E bind-mount data directories writable after
  creation so the non-root EthBFT container can persist committed state on
  Linux CI runners regardless of the host umask.

## v0.1.0 - 2026-07-19

### Added

- BFT consensus over complete Engine API V2 execution payloads.
- Canonical RLP proposal envelope under `pkg/protocol`.
- Independent `engine_newPayloadV2` validation in `ProcessProposal`.
- Execution-committing ABCI app hash.
- Commit-bound height and transaction persistence with fsync.
- Deterministic proposal timestamp, randomness, fee recipient, and transaction
  order validation.
- Structured JSON logging and strict consensus configuration validation.
- Docker E2E coverage for direct transactions, CometBFT-submitted transactions,
  non-executable candidates, and restart recovery.
- RFC 0001 describing the target multi-validator protocol.

### Changed

- Block production now happens in `PrepareProposal`; the asynchronous height
  polling and transaction-delivery loop has been removed.
- EL forkchoice advances only after CometBFT decides the execution proposal.
- Committed transactions report `included` immediately at ABCI `Commit`.
- Protocol v1 finalizes the decided EL block immediately and rejects local
  finality-depth overrides.
- Application version is now `0.1.0`.

### Removed

- Asynchronous post-consensus transaction retries and terminal delivery
  rejection semantics.
- Compatibility with v0.0.x state files and chain history.

### Limitations

- The default Compose stack remains a single-validator development network.
- Protocol v1 supports Shanghai/Engine API V2 only; blobs are disabled.
- Production state sync, dynamic validators, and external light-client proofs
  are not implemented.
