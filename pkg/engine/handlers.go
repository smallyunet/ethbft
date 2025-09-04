package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// Engine API method handlers

func (s *Server) handleNewPayload(params json.RawMessage) (interface{}, error) {
	var payload ExecutionPayload
	if err := json.Unmarshal(params, &[]interface{}{&payload}); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	log.Printf("Received new payload: block %s with state root %s", payload.BlockNumber, payload.StateRoot)

	// Execute the payload via ABCI
	if err := s.abciClient.ExecutePayload(context.Background(), &payload); err != nil {
		errMsg := err.Error()
		return PayloadStatus{
			Status:          "INVALID",
			LatestValidHash: nil,
			ValidationError: &errMsg,
		}, nil
	}

	s.latestPayload = &payload

	validHash := payload.BlockHash
	return PayloadStatus{
		Status:          "VALID",
		LatestValidHash: &validHash,
		ValidationError: nil,
	}, nil
}

func (s *Server) handleForkchoiceUpdated(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	if len(args) < 1 {
		return nil, fmt.Errorf("missing forkchoice state")
	}

	var state ForkchoiceState
	if err := json.Unmarshal(args[0], &state); err != nil {
		return nil, fmt.Errorf("invalid forkchoice state: %v", err)
	}

	log.Printf("Forkchoice updated: head=%s, safe=%s, finalized=%s",
		state.HeadBlockHash, state.SafeBlockHash, state.FinalizedBlockHash)

	// Update our state
	s.forkchoiceState = &state

	// Notify ABCI
	if err := s.abciClient.UpdateForkchoice(context.Background(), &state); err != nil {
		return nil, fmt.Errorf("failed to update forkchoice: %v", err)
	}

	response := ForkchoiceUpdatedResponse{
		PayloadStatus: PayloadStatus{
			Status:          "VALID",
			LatestValidHash: &state.HeadBlockHash,
			ValidationError: nil,
		},
		PayloadId: nil,
	}

	// If there are payload attributes, prepare a new payload
	if len(args) >= 2 {
		var attrs PayloadAttributes
		if err := json.Unmarshal(args[1], &attrs); err == nil {
			s.payloadCounter++
			payloadId := fmt.Sprintf("0x%x", s.payloadCounter)
			response.PayloadId = &payloadId

			log.Printf("Prepared payload with ID: %s", payloadId)
		}
	}

	return response, nil
}

func (s *Server) handleGetPayload(params json.RawMessage) (interface{}, error) {
	var payloadId string
	if err := json.Unmarshal(params, &[]interface{}{&payloadId}); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	log.Printf("Getting payload for ID: %s", payloadId)

	// Get payload from ABCI
	payload, err := s.abciClient.GetPendingPayload(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %v", err)
	}

	return payload, nil
}

func (s *Server) handleExchangeTransitionConfiguration(params json.RawMessage) (interface{}, error) {
	// Return default transition configuration
	return TransitionConfiguration{
		TerminalTotalDifficulty: "0x0",
		TerminalBlockHash:       "0x0000000000000000000000000000000000000000000000000000000000000000",
		TerminalBlockNumber:     "0x0",
	}, nil
}

func (s *Server) handleGetPayloadBodiesByHash(params json.RawMessage) (interface{}, error) {
	var blockHashes []string
	if err := json.Unmarshal(params, &[]interface{}{&blockHashes}); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	log.Printf("Getting payload bodies for hashes: %v", blockHashes)

	// Return empty array for now - in a real implementation, you'd look up the blocks
	return []interface{}{}, nil
}

func (s *Server) handleGetPayloadBodiesByRange(params json.RawMessage) (interface{}, error) {
	var args []interface{}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	if len(args) < 2 {
		return nil, fmt.Errorf("missing start and count parameters")
	}

	start, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid start parameter")
	}

	count, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid count parameter")
	}

	log.Printf("Getting payload bodies from %s, count %s", start, count)

	// Return empty array for now - in a real implementation, you'd look up the blocks
	return []interface{}{}, nil
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(w http.ResponseWriter, id interface{}, result interface{}, err error) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
	}

	if err != nil {
		resp.Error = &rpcError{
			Code:    -32000,
			Message: err.Error(),
		}
	} else {
		resp.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
