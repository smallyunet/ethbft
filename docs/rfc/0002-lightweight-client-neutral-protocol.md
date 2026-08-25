# RFC 0002: Lightweight client-neutral execution consensus

- **Status:** Implemented as protocol v2; production acceptance pending
- **Target:** EthBFT v0.3
- **Supersedes:** RFC 0001 protocol-v1 wire format

## Goal

Define the smallest deterministic interface that lets a BFT system decide
Ethereum execution without duplicating execution-client responsibilities or
depending on one client's private RPC extensions.

## Responsibilities

| Component | Owns |
| --- | --- |
| Execution client | EVM, state, txpool, transaction P2P, payload construction and validation |
| CometBFT | validator networking, proposal dissemination, votes, finality |
| EthBFT | deterministic payload envelope, Engine API lifecycle, commit recovery |

EthBFT MUST NOT maintain a user-transaction mempool or authoritative receipt
index. Users MUST submit transactions to an EL JSON-RPC endpoint. CometBFT MUST
run its transaction mempool in `nop` mode.

## Engine API profile

At startup the adapter calls `engine_exchangeCapabilities` and MUST stop if the
EL lacks methods required by any configured fork:

| Fork profile | Build | Retrieve | Validate |
| --- | --- | --- | --- |
| Shanghai | `forkchoiceUpdatedV2` | `getPayloadV2` | `newPayloadV2` |
| Cancun | `forkchoiceUpdatedV3` | `getPayloadV3` | `newPayloadV3` |
| Prague | `forkchoiceUpdatedV3` | `getPayloadV4` | `newPayloadV4` |

All calls use one JWT-authenticated endpoint. Client identification is
diagnostic only and MUST NOT alter consensus behavior.

## Proposal format

A proposal contains exactly one byte string:

```text
"ETHBFT" || 0x00 || 0x02 || RLP(protocol-v2 fields)
```

The RLP commits to Engine API version, chain ID, consensus height, previous app
hash, the complete execution payload, optional parent beacon block root,
versioned blob hashes, and Prague execution requests. Decoding MUST reject
non-canonical encoding, trailing bytes, unexpected fork fields, unordered
request types, a reconstructed block-hash mismatch, or a payload above the
configured limit.

## Lifecycle

1. `PrepareProposal` derives deterministic payload attributes from committed
   state and consensus height/time, asks the proposer EL to build, validates
   locally, and returns one envelope.
2. `ProcessProposal` requires exactly one envelope, validates all deterministic
   fields, reconstructs its Ethereum block hash, and calls the matching
   `newPayload` method. Only `VALID` is accepted.
3. `FinalizeBlock` repeats validation, persists a commit intent, and advances
   head/safe/finalized to the decided payload.
4. `Commit` atomically stores height, execution hash, and app hash and clears
   the intent. Startup replays a surviving intent.

## Determinism and upgrades

The protocol fingerprint covers chain ID, execution genesis, fork timestamps,
fee recipient, and maximum payload size. A mismatch MUST stop startup. Fork
schedule or envelope changes therefore require an explicit coordinated network
upgrade; automatic local inference is forbidden.

## Safety properties

- no payload is voted without local EL validation;
- no EL forkchoice is advanced before a BFT decision;
- `SYNCING`, `ACCEPTED`, malformed, timed-out, and inconsistent results are
  fail-closed;
- each validator uses an independent EL/datadir, with EthBFT as its sole
  forkchoice authority;
- readiness is false while either the EL or CometBFT is catching up.

## Non-goals

This protocol is not an Ethereum-mainnet bridge, beacon consensus client,
cross-chain proof system, wallet RPC proxy, block explorer, or validator
governance mechanism.

## Open production work

ABCI state sync, validator replacement, mixed-client conformance, Byzantine
fault injection, upgrade governance, load envelopes, and independent audit are
acceptance gates, not implicit properties of this RFC.
