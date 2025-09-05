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
	hdrFields, ok := s.headerData[root]
	s.blockMutex.RUnlock()
	if !ok { // fallback minimal
		hdrFields = beaconHeaderFields{Slot: slot, ParentRoot: zeroHash32(), StateRoot: s.latestBlockHash, BodyRoot: zeroHash32()}
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"root":      root,
			"canonical": true,
			"header": map[string]interface{}{
				"message": map[string]interface{}{
					"slot":           strconv.FormatInt(hdrFields.Slot, 10),
					"proposer_index": "0",
					"parent_root":    hdrFields.ParentRoot,
					"state_root":     hdrFields.StateRoot,
					"body_root":      hdrFields.BodyRoot,
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
	response.Data.CurrentForkVersion = "0x04000000" // Deneb
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
			"previous_version": "0x03000000", // capella
			"current_version":  "0x04000000", // deneb
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

	// Log the incoming request for debugging
	log.Printf("BEACON_REQUEST: handleBeaconBlock called with ID: %s", id)

	var (
		root  string
		found bool
	)

	s.blockMutex.RLock()
	if id == "head" {
		root = s.headRoot
		found = true
		log.Printf("BEACON_REQUEST: Request for 'head', using root: %s", root)
	} else if strings.HasPrefix(id, "0x") {
		normalizedId := normalizeRoot(id)
		if _, ok := s.rootSlots[normalizedId]; ok {
			root = normalizedId
			found = true
			log.Printf("BEACON_REQUEST: Found root %s in rootSlots mapping", root)
		} else {
			log.Printf("BEACON_REQUEST: Root %s NOT found in rootSlots mapping", normalizedId)
			// Print current rootSlots for debugging
			log.Printf("BEACON_REQUEST: Current rootSlots mappings:")
			for r, sl := range s.rootSlots {
				log.Printf("BEACON_REQUEST:   %s -> slot %d", r, sl)
			}
		}
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if rt, ok := s.slotRoots[n]; ok {
			root = rt
			found = true
			log.Printf("BEACON_REQUEST: Found slot %d -> root %s", n, root)
		} else {
			log.Printf("BEACON_REQUEST: Slot %d NOT found in slotRoots mapping", n)
		}
	}
	s.blockMutex.RUnlock()

	if !found {
		log.Printf("BEACON_REQUEST: Block not found for ID: %s", id)
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	hdrFields, ok := s.headerData[root]
	if !ok {
		// Use SSZ bytes as the only trusted source - never reconstruct from "latest"
		sszBytes, sszOk := s.loadBytesByRoot(root)
		if !sszOk {
			log.Printf("ERROR: No SSZ bytes found for root %s", root)
			http.Error(w, "Beacon block not found", http.StatusNotFound)
			return
		}

		// Unmarshal ONLY for extracting header fields
		blk, err := unmarshalSignedBeaconBlockSSZ(sszBytes)
		if err != nil {
			log.Printf("ERROR: Failed to unmarshal SSZ for root %s: %v", root, err)
			http.Error(w, "Corrupt beacon block", http.StatusInternalServerError)
			return
		}

		// Extract header fields from unmarshaled block
		bodyRoot := computeBeaconBodyRootDeneb(blk.Message.Body)
		hdrFields = beaconHeaderFields{
			Slot:       int64(blk.Message.Slot),
			ParentRoot: blk.Message.ParentRoot,
			StateRoot:  blk.Message.StateRoot,
			BodyRoot:   bodyRoot,
		}

		// Verify consistency
		rebuiltRoot := computeBeaconHeaderRoot(hdrFields)
		if rebuiltRoot != root {
			log.Printf("ERROR: Header root mismatch for %s: expected %s, got %s", root, root, rebuiltRoot)
			http.Error(w, "Beacon block root mismatch", http.StatusInternalServerError)
			return
		}

		// Cache for future use
		s.blockMutex.Lock()
		s.headerData[root] = hdrFields
		s.blockMutex.Unlock()

		log.Printf("Successfully extracted header data from SSZ for root %s", root)
	}

	// For hard self-check, we need to get the SSZ bytes and unmarshal the block
	sszBytes, sszOk := s.loadBytesByRoot(root)
	if !sszOk {
		log.Printf("ERROR: No SSZ bytes found for hard self-check, root %s", root)
		http.Error(w, "Beacon block not found", http.StatusInternalServerError)
		return
	}

	// Unmarshal for hard self-check validation
	blk, err := unmarshalSignedBeaconBlockSSZ(sszBytes)
	if err != nil {
		log.Printf("ERROR: Failed to unmarshal SSZ for hard self-check, root %s: %v", root, err)
		http.Error(w, "Corrupt beacon block", http.StatusInternalServerError)
		return
	}

	// HARD SELF-CHECK: Validate body root before returning response
	if err := hardSelfCheckBeaconBlockBody(blk, hdrFields.BodyRoot); err != nil {
		log.Printf("CRITICAL: %v", err)
		http.Error(w, "body_root mismatch", http.StatusInternalServerError)
		return
	}

	// HARD SELF-CHECK: Validate full block root before returning response
	if err := hardSelfCheckBeaconBlock(blk, root); err != nil {
		log.Printf("CRITICAL: %v", err)
		http.Error(w, "block_root mismatch", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           strconv.FormatInt(hdrFields.Slot, 10),
				"proposer_index": "0",
				"parent_root":    hdrFields.ParentRoot,
				"state_root":     hdrFields.StateRoot,
				"body_root":      hdrFields.BodyRoot,
			},
			"signature": zeroSig96(),
		},
	}
	if true { // toggle to true for per-request debug
		log.Printf("DEBUG serve block root=%s slot=%d parent=%s state=%s body=%s", root, hdrFields.Slot, hdrFields.ParentRoot, hdrFields.StateRoot, hdrFields.BodyRoot)
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

	var (
		slot  int64
		root  string
		found bool
	)
	s.blockMutex.RLock()
	if id == "head" {
		slot = s.latestBlockHeight
		root = s.headRoot
		found = true
	} else if strings.HasPrefix(id, "0x") {
		if sl, ok := s.rootSlots[normalizeRoot(id)]; ok {
			slot = sl
			root = normalizeRoot(id)
			found = true
		}
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if rt, ok := s.slotRoots[n]; ok {
			slot = n
			root = rt
			found = true
		}
	}
	s.blockMutex.RUnlock()
	if !found {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	// Defensive: ensure mapping present (id might have been head when first requested)
	s.blockMutex.Lock()
	if _, ok := s.rootSlots[root]; !ok {
		s.rootSlots[root] = slot
	}
	if _, ok := s.slotRoots[slot]; !ok {
		s.slotRoots[slot] = root
	}
	s.blockMutex.Unlock()

	hdrFields2, ok := s.headerData[root]
	if !ok {
		// When header data is not found, use the latest execution state root instead of the beacon header root
		s.blockMutex.RLock()
		execStateRoot := s.latestBlockHash // This should be the execution state root
		s.blockMutex.RUnlock()

		// Create a complete BeaconBlockBody for proper SSZ computation
		fallbackPayload := &ExecutionPayload{
			StateRoot:     execStateRoot,
			BlockNumber:   fmt.Sprintf("0x%x", slot),
			Timestamp:     "0x0",
			ParentHash:    "0x0000000000000000000000000000000000000000000000000000000000000000",
			FeeRecipient:  "0x0000000000000000000000000000000000000000",
			ReceiptsRoot:  "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			LogsBloom:     "0x" + strings.Repeat("0", 512),
			PrevRandao:    "0x0000000000000000000000000000000000000000000000000000000000000000",
			GasLimit:      "0x1388",
			GasUsed:       "0x0",
			ExtraData:     "0x",
			BaseFeePerGas: "0x0",
			BlockHash:     "0x0000000000000000000000000000000000000000000000000000000000000000",
			Transactions:  []string{},
		}
		body := &BeaconBlockBody{
			ExecutionPayload: fallbackPayload,
			// All other fields are zero/empty by default
		}
		bodyRoot := computeBeaconBodyRootDeneb(body)
		hdrFields2 = beaconHeaderFields{Slot: slot, ParentRoot: zeroHash32(), StateRoot: execStateRoot, BodyRoot: bodyRoot}
		log.Printf("WARNING: Header data not found for root %s in handleBeaconHeader, using fallback with execStateRoot %s", root, execStateRoot)
	}
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"root":      root,
			"canonical": true,
			"header": map[string]interface{}{
				"message": map[string]interface{}{
					"slot":           strconv.FormatInt(hdrFields2.Slot, 10),
					"proposer_index": "0",
					"parent_root":    hdrFields2.ParentRoot,
					"state_root":     hdrFields2.StateRoot,
					"body_root":      hdrFields2.BodyRoot,
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

	// Debug: log incoming Geth request and current state
	log.Printf("GETH_REQUEST: Geth requesting beacon block for ID: %s", id)
	log.Printf("GETH_REQUEST: Full URL path: %s", r.URL.Path)

	// Show our current state for debugging
	s.blockMutex.RLock()
	log.Printf("GETH_REQUEST: Our current rootSlots map has %d entries", len(s.rootSlots))
	log.Printf("GETH_REQUEST: Our current slotRoots map has %d entries", len(s.slotRoots))
	log.Printf("GETH_REQUEST: Latest block height: %d, head root: %s", s.latestBlockHeight, s.headRoot)
	// Show some recent roots
	for i := s.latestBlockHeight - 3; i <= s.latestBlockHeight; i++ {
		if root, exists := s.slotRoots[i]; exists {
			log.Printf("GETH_REQUEST: Slot %d -> Root %s", i, root)
		}
	}
	s.blockMutex.RUnlock()

	var root string
	if id == "head" {
		s.blockMutex.RLock()
		root = s.headRoot
		s.blockMutex.RUnlock()
	} else if strings.HasPrefix(id, "0x") {
		root = normalizeRoot(id)
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		s.blockMutex.RLock()
		if rt, ok := s.slotRoots[n]; ok {
			root = rt
		}
		s.blockMutex.RUnlock()
	} else {
		http.Error(w, "Invalid block ID", http.StatusBadRequest)
		return
	}
	if root == "" {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	// Retrieve stored SSZ bytes (only trusted source)
	sszBytes, ok := s.loadBytesByRoot(root)
	if !ok {
		log.Printf("BLOCK_NOT_FOUND: no stored SSZ for root %s", root)
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	// Unmarshal ONLY for JSON conversion (persisted SSZ is single source of truth)
	blk, err := unmarshalSignedBeaconBlockSSZ(sszBytes)
	if err != nil {
		log.Printf("UNMARSHAL_ERROR: root=%s err=%v", root, err)
		http.Error(w, "corrupt block", http.StatusInternalServerError)
		return
	}

	// Self-check A: body_root
	bodyRoot := computeBeaconBodyRootDeneb(blk.Message.Body)
	// Header root recompute & compare (block root)
	recalcRoot := computeSignedBeaconBlockRoot(blk)
	if recalcRoot != root {
		log.Printf("BLOCK_ROOT_MISMATCH param=%s recalc=%s", root, recalcRoot)
		http.Error(w, "block_root mismatch", http.StatusInternalServerError)
		return
	}

	// Log per-field roots (compute function already prints execution & body field roots)
	logBlockFieldRoots(blk, root)

	// HARD SELF-CHECK: Validate body root before returning response
	if err := hardSelfCheckBeaconBlockBody(blk, bodyRoot); err != nil {
		log.Printf("CRITICAL: %v", err)
		http.Error(w, "body_root mismatch", http.StatusInternalServerError)
		return
	}

	// HARD SELF-CHECK: Validate full block root before returning response
	if err := hardSelfCheckBeaconBlock(blk, root); err != nil {
		log.Printf("CRITICAL: %v", err)
		http.Error(w, "block_root mismatch", http.StatusInternalServerError)
		return
	}

	// Build JSON strictly from blk (no latest lookups)
	resp := map[string]interface{}{
		"version": "deneb",
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           fmt.Sprintf("%d", blk.Message.Slot),
				"proposer_index": fmt.Sprintf("%d", blk.Message.ProposerIndex),
				"parent_root":    blk.Message.ParentRoot,
				"state_root":     blk.Message.StateRoot,
				"body_root":      bodyRoot,
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
					"sync_aggregate": map[string]interface{}{
						"sync_committee_bits":      zeroHexBytes(64),
						"sync_committee_signature": zeroSig96(),
					},
					"execution_payload": map[string]interface{}{
						"parent_hash":              blk.Message.Body.ExecutionPayload.ParentHash,
						"fee_recipient":            blk.Message.Body.ExecutionPayload.FeeRecipient,
						"state_root":               blk.Message.Body.ExecutionPayload.StateRoot,
						"receipts_root":            blk.Message.Body.ExecutionPayload.ReceiptsRoot,
						"logs_bloom":               blk.Message.Body.ExecutionPayload.LogsBloom,
						"prev_randao":              blk.Message.Body.ExecutionPayload.PrevRandao,
						"block_number":             blk.Message.Body.ExecutionPayload.BlockNumber,
						"gas_limit":                blk.Message.Body.ExecutionPayload.GasLimit,
						"gas_used":                 blk.Message.Body.ExecutionPayload.GasUsed,
						"timestamp":                blk.Message.Body.ExecutionPayload.Timestamp,
						"extra_data":               blk.Message.Body.ExecutionPayload.ExtraData,
						"base_fee_per_gas":         blk.Message.Body.ExecutionPayload.BaseFeePerGas,
						"block_hash":               blk.Message.Body.ExecutionPayload.BlockHash,
						"transactions":             []interface{}{},
						"withdrawals":              []interface{}{},
						"blob_gas_used":            blk.Message.Body.ExecutionPayload.BlobGasUsed,
						"excess_blob_gas":          blk.Message.Body.ExecutionPayload.ExcessBlobGas,
						"parent_beacon_block_root": blk.Message.Body.ExecutionPayload.ParentBeaconBlockRoot,
					},
					"blob_kzg_commitments": []interface{}{},
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
			"current_fork_version":    "0x04000000", // Deneb
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
