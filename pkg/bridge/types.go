package bridge

import (
	"github.com/ethereum/go-ethereum/beacon/engine"
)

// Use official go-ethereum engine types to avoid schema drift.
type ExecutionPayload = engine.ExecutableData     // Covers post-Shanghai payload (includes withdrawals)
type ForkchoiceState = engine.ForkchoiceStateV1   // V1 is enough for minimal demo
type PayloadAttributes = engine.PayloadAttributes // Geth will interpret fields per current fork
