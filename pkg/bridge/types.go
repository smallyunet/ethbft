package bridge

import (
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Use official go-ethereum engine types to avoid schema drift.
type ExecutionPayload = engine.ExecutableData     // Covers post-Shanghai payload (includes withdrawals)
type ForkchoiceState = engine.ForkchoiceStateV1   // V1 is enough for minimal demo
type PayloadAttributes = engine.PayloadAttributes // Geth will interpret fields per current fork

// Shared Engine API types for bridge consistency
type FCURequest struct {
	Head      common.Hash `json:"headBlockHash"`
	Safe      common.Hash `json:"safeBlockHash"`
	Finalized common.Hash `json:"finalizedBlockHash"`
}

type FCUResponse struct {
	PayloadStatus PayloadStatus  `json:"payloadStatus"`
	PayloadID     *hexutil.Bytes `json:"payloadId"`
}

type PayloadStatus struct {
	Status          string `json:"status"`
	LatestValidHash string `json:"latestValidHash"`
	ValidationError string `json:"validationError"`
}
