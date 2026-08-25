# Execution-client compatibility

EthBFT compatibility is capability- and test-based, not brand-based. A client
must expose authenticated chain/block/sync RPCs, capability exchange, and the
configured Engine API method profile with specification-conforming payload
serialization and status behavior.

## Current matrix

| Client | Build/validation evidence | Status |
| --- | --- | --- |
| Geth | Bundled Shanghai single-validator Docker E2E | Reference integration |
| Reth | Not yet in continuous CI | Candidate |
| Nethermind | Not yet in continuous CI | Candidate |
| Besu | Not yet in continuous CI | Candidate |
| Erigon | Not yet in continuous CI | Candidate |

“Candidate” does not mean unsupported by design; it means the project has not
yet earned a release-level compatibility claim.

## Graduation rule

A client/fork pair becomes supported only after capability negotiation,
payload build/validation, transaction inclusion, restart recovery, malformed
proposal rejection, and fork-boundary cases pass in continuous CI. Version
ranges and known deviations must be recorded here before release.

Hive Engine API suites should be the external conformance baseline. EthBFT's
mixed-client network tests must additionally cover the BFT lifecycle and crash
boundaries that Engine API conformance alone cannot cover.
