package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Beacon API handlers

func (s *Server) handleHeadHeader(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	slot := s.latestBlockHeight
	root := s.headRoot
	s.blockMutex.RUnlock()

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"root":      root,
			"canonical": true,
			"header": map[string]interface{}{
				"message": map[string]interface{}{
					"slot":           strconv.FormatInt(slot, 10),
					"proposer_index": "0",
					"parent_root":    zeroHash32(),
					"state_root":     root,
					"body_root":      zeroHash32(),
				},
				"signature": zeroSig96(),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBeaconState(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	response := BeaconStateResponse{}
	response.Data.GenesisValidatorsRoot = "0x0000000000000000000000000000000000000000000000000000000000000000"
	response.Data.GenesisTime = "0"
	// Use proper Ethereum fork versions - these are the actual fork versions used by Ethereum
	response.Data.GenesisForkVersion = "0x00000000"
	response.Data.CurrentForkVersion = "0x02000000" // Bellatrix fork version
	response.Data.Slot = strconv.FormatInt(currentHeight, 10)
	response.Data.Epoch = strconv.FormatInt(currentHeight/32, 10) // Assuming 32 slots per epoch
	response.Data.FinalizedCheckpoint.Epoch = strconv.FormatInt(currentHeight/32, 10)
	response.Data.FinalizedCheckpoint.Root = currentHash
	response.Data.CurrentJustifiedCheckpoint.Epoch = strconv.FormatInt(currentHeight/32, 10)
	response.Data.CurrentJustifiedCheckpoint.Root = currentHash
	response.Data.PreviousJustifiedCheckpoint.Epoch = strconv.FormatInt(currentHeight/32, 10)
	response.Data.PreviousJustifiedCheckpoint.Root = currentHash

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconForks(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"previous_version": "0x00000000",
			"current_version":  "0x00000000", // phase0
			"epoch":            "0",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLightClientBootstrap(w http.ResponseWriter, r *http.Request) {
	// Extract block root from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		http.Error(w, "Invalid block root", http.StatusBadRequest)
		return
	}
	// blockRoot := parts[len(parts)-1] // Not used currently

	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	// Generate consistent header roots
	parentRoot := "0x0000000000000000000000000000000000000000000000000000000000000000"
	stateRoot := currentHash
	bodyRoot := "0x0000000000000000000000000000000000000000000000000000000000000000"

	response := map[string]interface{}{
		"data": map[string]interface{}{
			"header": map[string]interface{}{
				"beacon": map[string]interface{}{
					"slot":           strconv.FormatInt(currentHeight, 10),
					"proposer_index": "0",
					"parent_root":    parentRoot,
					"state_root":     stateRoot,
					"body_root":      bodyRoot,
				},
			},
			"current_sync_committee": map[string]interface{}{
				"pubkeys": []string{
					"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				},
				"aggregate_pubkey": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
			"current_sync_committee_branch": []string{
				"0x0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconBlock(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid block ID", http.StatusBadRequest)
		return
	}
	id := parts[len(parts)-1]

	s.blockMutex.RLock()
	slot := s.latestBlockHeight
	root := s.headRoot
	if id == "head" {
		// current
	} else if strings.HasPrefix(id, "0x") {
		if sl, ok := s.rootSlots[normalizeRoot(id)]; ok {
			slot = sl
			root = normalizeRoot(id)
		}
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if rt, ok := s.slotRoots[n]; ok {
			slot = n
			root = rt
		}
	}
	s.blockMutex.RUnlock()

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           strconv.FormatInt(slot, 10),
				"proposer_index": "0",
				"parent_root":    zeroHash32(),
				"state_root":     root,
				"body_root":      zeroHash32(),
			},
			"signature": zeroSig96(),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBeaconHeader(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid block ID", http.StatusBadRequest)
		return
	}
	id := parts[len(parts)-1]

	s.blockMutex.RLock()
	slot := s.latestBlockHeight
	root := s.headRoot
	if id == "head" {
	} else if strings.HasPrefix(id, "0x") {
		if sl, ok := s.rootSlots[normalizeRoot(id)]; ok {
			slot = sl
			root = normalizeRoot(id)
		}
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if rt, ok := s.slotRoots[n]; ok {
			slot = n
			root = rt
		}
	}
	s.blockMutex.RUnlock()

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"root":      root,
			"canonical": true,
			"header": map[string]interface{}{
				"message": map[string]interface{}{
					"slot":           strconv.FormatInt(slot, 10),
					"proposer_index": "0",
					"parent_root":    zeroHash32(),
					"state_root":     root,
					"body_root":      zeroHash32(),
				},
				"signature": zeroSig96(),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBeaconBlockV2(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid block ID", http.StatusBadRequest)
		return
	}
	id := parts[len(parts)-1]

	s.blockMutex.RLock()
	slot := s.latestBlockHeight
	root := s.headRoot
	if id != "head" {
		if strings.HasPrefix(id, "0x") {
			if sl, ok := s.rootSlots[normalizeRoot(id)]; ok {
				slot = sl
				root = normalizeRoot(id)
			}
		} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			if rt, ok := s.slotRoots[n]; ok {
				slot = n
				root = rt
			}
		}
	}
	s.blockMutex.RUnlock()

	resp := map[string]interface{}{
		"version": "phase0",
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           strconv.FormatInt(slot, 10),
				"proposer_index": "0",
				"parent_root":    zeroHash32(),
				"state_root":     root,
				"body": map[string]interface{}{
					"randao_reveal": zeroSig96(),
					"eth1_data": map[string]interface{}{
						"deposit_root":  zeroHash32(),
						"deposit_count": "0",
						"block_hash":    zeroHash32(),
					},
					"graffiti":           zeroHash32(),
					"proposer_slashings": []interface{}{},
					"attester_slashings": []interface{}{},
					"attestations":       []interface{}{},
					"deposits":           []interface{}{},
					"voluntary_exits":    []interface{}{},
				},
			},
			"signature": zeroSig96(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBeaconHeaderV2(w http.ResponseWriter, r *http.Request) {
	// Extract block ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid block ID", http.StatusBadRequest)
		return
	}
	blockId := parts[len(parts)-1]

	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	// If requesting "head", use current block
	if blockId == "head" {
		blockId = strconv.FormatInt(currentHeight, 10)
	}

	response := BeaconHeadResponse{}
	response.Data.ExecutionOptimistic = false
	response.Data.Finalized = false
	response.Data.Header.Slot = blockId
	response.Data.Header.ProposerIndex = "0"
	response.Data.Header.ParentRoot = "0x0000000000000000000000000000000000000000000000000000000000000000"
	response.Data.Header.StateRoot = currentHash
	response.Data.Header.BodyRoot = "0x0000000000000000000000000000000000000000000000000000000000000000"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconGenesis(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"genesis_time":            "0",
			"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"genesis_fork_version":    "0x00000000",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconValidators(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"index":   "0",
				"balance": "32000000000",
				"status":  "active_ongoing",
				"validator": map[string]interface{}{
					"pubkey":                       "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"withdrawal_credentials":       "0x0000000000000000000000000000000000000000000000000000000000000000",
					"effective_balance":            "32000000000",
					"slashed":                      false,
					"activation_eligibility_epoch": "0",
					"activation_epoch":             "0",
					"exit_epoch":                   "18446744073709551615",
					"withdrawable_epoch":           "18446744073709551615",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconCheckpoint(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	root := s.headRoot
	s.blockMutex.RUnlock()

	checkpointEpoch := currentHeight / 32
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"epoch": strconv.FormatInt(checkpointEpoch, 10),
			"root":  root,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBeaconSyncCommittees(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"validators": []string{"0"},
			"validator_aggregates": []map[string]interface{}{
				{
					"validator_indices":                []string{"0"},
					"validator_sync_committee_indices": []string{"0"},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleBeaconStateByState(w http.ResponseWriter, r *http.Request) {
	// Extract state ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid state ID", http.StatusBadRequest)
		return
	}
	stateId := parts[len(parts)-1]

	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	// If requesting "head", use current block
	if stateId == "head" {
		stateId = strconv.FormatInt(currentHeight, 10)
	}

	response := map[string]interface{}{
		"data": map[string]interface{}{
			"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"genesis_time":            "0",
			"genesis_fork_version":    "0x00000000",
			"current_fork_version":    "0x02000000", // Bellatrix fork version
			"slot":                    stateId,
			"epoch":                   strconv.FormatInt(currentHeight/32, 10),
			"finalized_checkpoint": map[string]interface{}{
				"epoch": strconv.FormatInt(currentHeight/32, 10),
				"root":  currentHash,
			},
			"current_justified_checkpoint": map[string]interface{}{
				"epoch": strconv.FormatInt(currentHeight/32, 10),
				"root":  currentHash,
			},
			"previous_justified_checkpoint": map[string]interface{}{
				"epoch": strconv.FormatInt(currentHeight/32, 10),
				"root":  currentHash,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLightClientUpdates(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	response := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"attested_header": map[string]interface{}{
					"beacon": map[string]interface{}{
						"slot":           strconv.FormatInt(currentHeight, 10),
						"proposer_index": "0",
						"parent_root":    "0x0000000000000000000000000000000000000000000000000000000000000000",
						"state_root":     currentHash,
						"body_root":      "0x0000000000000000000000000000000000000000000000000000000000000000",
					},
				},
				"next_sync_committee": map[string]interface{}{
					"pubkeys": []string{
						"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					},
					"aggregate_pubkey": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				},
				"next_sync_committee_branch": []string{
					"0x0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLightClientFinalityUpdate(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	response := map[string]interface{}{
		"data": map[string]interface{}{
			"attested_header": map[string]interface{}{
				"beacon": map[string]interface{}{
					"slot":           strconv.FormatInt(currentHeight, 10),
					"proposer_index": "0",
					"parent_root":    "0x0000000000000000000000000000000000000000000000000000000000000000",
					"state_root":     currentHash,
					"body_root":      "0x0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
			"finalized_header": map[string]interface{}{
				"beacon": map[string]interface{}{
					"slot":           strconv.FormatInt(currentHeight, 10),
					"proposer_index": "0",
					"parent_root":    "0x0000000000000000000000000000000000000000000000000000000000000000",
					"state_root":     currentHash,
					"body_root":      "0x0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
			"finality_branch": []string{
				"0x0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLightClientOptimisticUpdate(w http.ResponseWriter, r *http.Request) {
	s.blockMutex.RLock()
	currentHeight := s.latestBlockHeight
	currentHash := s.latestBlockHash
	s.blockMutex.RUnlock()

	response := map[string]interface{}{
		"data": map[string]interface{}{
			"attested_header": map[string]interface{}{
				"beacon": map[string]interface{}{
					"slot":           strconv.FormatInt(currentHeight, 10),
					"proposer_index": "0",
					"parent_root":    "0x0000000000000000000000000000000000000000000000000000000000000000",
					"state_root":     currentHash,
					"body_root":      "0x0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleEventsStream handles the events stream for Beacon API
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	eventChan := make(chan []byte, 10)
	s.eventClientsMux.Lock()
	s.eventClients[eventChan] = true
	s.eventClientsMux.Unlock()
	defer func() {
		s.eventClientsMux.Lock()
		delete(s.eventClients, eventChan)
		s.eventClientsMux.Unlock()
		close(eventChan)
	}()

	s.blockMutex.RLock()
	slot := s.latestBlockHeight
	root := s.headRoot
	s.blockMutex.RUnlock()
	if slot > 0 && root != "" {
		initEvent := map[string]interface{}{
			"slot":             fmt.Sprintf("%d", slot),
			"block":            root,
			"state":            root,
			"epoch_transition": false,
		}
		b, _ := json.Marshal(initEvent)
		fmt.Fprintf(w, "event: head\ndata: %s\n\n", b)
		flusher.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("Client disconnected from events stream")
			return
		case ev := <-eventChan:
			fmt.Fprintf(w, "event: head\ndata: %s\n\n", ev)
			flusher.Flush()
		}
	}
}

// broadcastHeadEvent sends a head event to all connected event stream clients
func (s *Server) broadcastHeadEvent(height int64, hashOrRoot string) {
	event := map[string]interface{}{
		"slot":             fmt.Sprintf("%d", height),
		"block":            hashOrRoot,
		"state":            hashOrRoot,
		"epoch_transition": false,
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("marshal head event: %v", err)
		return
	}

	s.eventClientsMux.Lock()
	defer s.eventClientsMux.Unlock()
	for ch := range s.eventClients {
		select {
		case ch <- data:
		default:
			delete(s.eventClients, ch)
			close(ch)
		}
	}
}
