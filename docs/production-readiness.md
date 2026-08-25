# Production readiness

The v0.3 architecture is production-oriented; the current alpha is not
production-ready. A release may remove that label only when evidence for every
required gate is linked from this page.

## Required gates

- [ ] 4+ validator multi-host network with independent ELs and datadirs
- [ ] Mixed-client and per-fork continuous compatibility matrix
- [ ] Byzantine proposer, invalid payload, equivocation, and malformed RLP tests
- [ ] Network partition, delayed Engine API, process kill, disk-full, and
      `FinalizeBlock`/`Commit` crash tests
- [ ] Validator bootstrap/replacement and ABCI snapshot state-sync procedure
- [ ] Coordinated fork, protocol, binary, and validator-set upgrade runbooks
- [ ] Sustained throughput and worst-case payload resource benchmarks
- [ ] Metrics and alerts for lag, sync, rejection, RPC failure, recovery, disk,
      memory, and consensus liveness
- [ ] Backup/restore, key isolation, JWT rotation, and incident response drills
- [ ] Threat model and independent security audit with resolved findings
- [ ] Reproducible builds, SBOM, signed artifacts, and rollback rehearsal

## Deployment invariants

Engine API is never public. Each validator's EthBFT process is the only
forkchoice authority for its dedicated EL. Protocol configuration, execution
genesis, and CometBFT genesis are release artifacts. Readiness, not liveness,
controls validator admission.
