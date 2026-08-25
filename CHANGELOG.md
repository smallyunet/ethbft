# Changelog

## v0.3.0-alpha.1 - Unreleased

### Changed

- Rebooted the project around protocol v2: one canonical full execution
  envelope per CometBFT height and no EthBFT/CometBFT user-transaction mempool.
- Added Engine API capability negotiation and versioned Shanghai V2, Cancun
  V3, and Prague V4 payload handling.
- Replaced client-specific dual RPC configuration with one standard
  JWT-authenticated Engine API endpoint.
- Reduced durable state to the consensus checkpoint and crash-recoverable
  commit intent; removed delivery/history indexing.
- Made observability services optional and removed the default explorer.
- Added explicit compatibility policy, protocol RFC, security boundary, and
  production-readiness gates.

### Compatibility

- Protocol v2 and state format 5 require a new chain or an explicit migration.
- Geth/Shanghai is the current reference integration. Other clients and later
  fork profiles remain candidates until continuous compatibility tests pass.

## v0.2.0 - 2026-08-25

### Changed

- Rewrote the EthBFT application, Engine API client, ABCI++ server, protocol
  codec, state persistence, health endpoints, metrics, and E2E harness in Rust.
- Preserved the protocol-v1 RLP proposal envelope byte-for-byte with a Go/Rust
  golden fixture.
- Replaced the unjournaled FinalizeBlock-to-Commit window with a durable,
  replayable execution commit intent.
- Kept CometBFT v0.38 as the default consensus engine and isolated the
  execution core behind a consensus-neutral Rust trait.
- Replaced Go CI, builds, tests, and Docker packaging with Cargo equivalents.

### Compatibility

- Requires a new chain: the Rust state format is version 4 and is intentionally
  incompatible with the v0.1.x JSON state file.
- Protocol v1 remains Shanghai-only and uses Engine API V2.

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
