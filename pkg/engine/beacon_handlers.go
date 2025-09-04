package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
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

	var (
		root  string
		found bool
	)

	s.blockMutex.RLock()
	if id == "head" {
		root = s.headRoot
		found = true
	} else if strings.HasPrefix(id, "0x") {
		if _, ok := s.rootSlots[normalizeRoot(id)]; ok {
			root = normalizeRoot(id)
			found = true
		}
	} else if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if rt, ok := s.slotRoots[n]; ok {
			root = rt
			found = true
		}
	}
	s.blockMutex.RUnlock()

	if !found {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	hdrFields, ok := s.headerData[root]
	if !ok {
		// When header data is not found, try to rebuild it from current state
		// This prevents hash mismatch errors when GETH requests a beacon block by hash
		log.Printf("WARNING: Header data not found for root %s, attempting to rebuild", root)

		// Try to find the slot from rootSlots mapping
		var slot int64
		if sl, exists := s.rootSlots[root]; exists {
			slot = sl
		} else {
			log.Printf("ERROR: Could not find slot for root %s", root)
			http.Error(w, "Beacon block not found", http.StatusNotFound)
			return
		}

		// Try to rebuild the header data
		s.blockMutex.RLock()
		execStateRoot := s.latestBlockHash
		parentRoot := "0x0000000000000000000000000000000000000000000000000000000000000000"
		if slot > 0 {
			// Try to find parent from previous slot
			if prevRoot, exists := s.slotRoots[slot-1]; exists {
				parentRoot = prevRoot
			}
		}
		s.blockMutex.RUnlock()

		bodyRoot := computeBeaconBodyRootWithStateRoot(&ExecutionPayload{StateRoot: execStateRoot})
		hdrFields = beaconHeaderFields{
			Slot:       slot,
			ParentRoot: parentRoot,
			StateRoot:  execStateRoot,
			BodyRoot:   bodyRoot,
		}

		// Verify that the rebuilt header produces the expected root
		rebuiltRoot := computeBeaconHeaderRoot(hdrFields)
		if rebuiltRoot != root {
			log.Printf("ERROR: Rebuilt header root %s does not match expected root %s", rebuiltRoot, root)
			http.Error(w, "Beacon block root mismatch", http.StatusNotFound)
			return
		}

		// Store the rebuilt header data for future use
		s.blockMutex.Lock()
		s.headerData[root] = hdrFields
		s.blockMutex.Unlock()

		log.Printf("Successfully rebuilt header data for root %s", root)
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
		hdrFields2 = beaconHeaderFields{Slot: slot, ParentRoot: zeroHash32(), StateRoot: execStateRoot, BodyRoot: zeroHash32()}
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
	// Defensive insert
	s.blockMutex.Lock()
	if _, ok := s.rootSlots[root]; !ok {
		s.rootSlots[root] = slot
	}
	if _, ok := s.slotRoots[slot]; !ok {
		s.slotRoots[slot] = root
	}
	s.blockMutex.Unlock()

	// Generate consistent timestamp for both SSZ calculation and JSON response
	currentTimestamp := uint64(time.Now().Unix())

	// Try to get the actual execution payload from Geth for accurate beacon block body
	var actualPayload *ExecutionPayload
	if payload, err := s.abciClient.GetPendingPayload(context.Background()); err == nil {
		actualPayload = payload
		log.Printf("DEBUG: Got actual execution payload for JSON response: parentHash=%s, stateRoot=%s, blockNumber=%s",
			payload.ParentHash, payload.StateRoot, payload.BlockNumber)
	} else {
		log.Printf("WARNING: Could not get execution payload for JSON response: %v", err)
	}

	hdrFields3, ok := s.headerData[root]
	if !ok {
		// When header data is not found, use the latest execution state root instead of the beacon header root
		s.blockMutex.RLock()
		execStateRoot := s.latestBlockHash // This should be the execution state root
		s.blockMutex.RUnlock()

		// Calculate the correct body root with the actual execution payload data
		var bodyRoot string
		if actualPayload != nil {
			// Use the COMPLETE execution payload for body root calculation to match JSON response
			bodyRoot = computeBeaconBodyRootWithRealPayload(actualPayload)
			log.Printf("BODY_ROOT_CALC: Using complete execution payload for SSZ calculation (fallback)")
		} else {
			// Fallback to using the simple state root method
			bodyRoot = computeBeaconBodyRootWithStateRoot(&ExecutionPayload{StateRoot: execStateRoot})
			log.Printf("BODY_ROOT_CALC: Using fallback method (no execution payload)")
		}

		hdrFields3 = beaconHeaderFields{Slot: slot, ParentRoot: zeroHash32(), StateRoot: execStateRoot, BodyRoot: bodyRoot}
		log.Printf("WARNING: Header data not found for root %s, using fallback with execStateRoot %s, bodyRoot %s", root, execStateRoot, bodyRoot)
	} else {
		// CRITICAL: Do NOT recalculate body root when serving beacon blocks
		// The body root must remain exactly as it was when the beacon block root was originally computed
		// Any changes to body root will cause beacon block root mismatch errors from geth
		log.Printf("BODY_ROOT_CALC: Using existing body root (no recalculation): %s", hdrFields3.BodyRoot)
	}

	// Debug: log the state root being used in the beacon block
	log.Printf("DEBUG: BeaconBlockV2 using StateRoot: %s, BodyRoot: %s for root %s", hdrFields3.StateRoot, hdrFields3.BodyRoot, root)

	// CRITICAL: Recalculate beacon block root based on the header fields we're actually returning
	actualBeaconRoot := computeBeaconHeaderRoot(hdrFields3)

	// Debug: log the final beacon block response that will be sent to Geth
	log.Printf("BEACON_RESPONSE: Returning beacon block for slot %d with:", hdrFields3.Slot)
	log.Printf("BEACON_RESPONSE:   - slot: %d", hdrFields3.Slot)
	log.Printf("BEACON_RESPONSE:   - parent_root: %s", hdrFields3.ParentRoot)
	log.Printf("BEACON_RESPONSE:   - state_root: %s", hdrFields3.StateRoot)
	log.Printf("BEACON_RESPONSE:   - body_root: %s", hdrFields3.BodyRoot)
	log.Printf("BEACON_RESPONSE:   - beacon_block_root (stored): %s", root)
	log.Printf("BEACON_RESPONSE:   - beacon_block_root (recalculated): %s", actualBeaconRoot)
	if root != actualBeaconRoot {
		log.Printf("BEACON_RESPONSE: WARNING - Root mismatch! Stored: %s, Calculated: %s", root, actualBeaconRoot)
	}

	resp := map[string]interface{}{
		"version": "deneb", // Critical field specifying the fork version
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           strconv.FormatInt(hdrFields3.Slot, 10),
				"proposer_index": "0",
				"parent_root":    hdrFields3.ParentRoot,
				"state_root":     hdrFields3.StateRoot,
				"body_root":      hdrFields3.BodyRoot, // Critical: beacon header must include body_root for hash calculation
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

					// Required since Altair fork
					"sync_aggregate": map[string]interface{}{
						"sync_committee_bits":      zeroHexBytes(64), // 512 bits
						"sync_committee_signature": zeroSig96(),
					},

					// Required for Deneb: execution_payload structure must match the data used for body_root calculation
					// CRITICAL: Use consistent data structure that matches our SSZ body_root calculation
					"execution_payload": map[string]interface{}{
						"parent_hash":              zeroHash32(),
						"fee_recipient":            zeroHexBytes(20),                                                     // address
						"state_root":               hdrFields3.StateRoot,                                                 // Must match the state_root used in body_root calculation
						"receipts_root":            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", // Empty tree root
						"logs_bloom":               zeroBloom256(),                                                       // 256 bytes
						"prev_randao":              zeroHash32(),
						"block_number":             fmt.Sprintf("0x%x", slot),             // Use actual slot as block number
						"gas_limit":                "0x1388",                              // Hexadecimal format (5000)
						"gas_used":                 "0x0",                                 // Hexadecimal format
						"timestamp":                fmt.Sprintf("0x%x", currentTimestamp), // Use the same timestamp as SSZ calculation
						"extra_data":               "0x",
						"base_fee_per_gas":         "0x0", // Hexadecimal format
						"block_hash":               zeroHash32(),
						"transactions":             []interface{}{},
						"withdrawals":              []interface{}{}, // Added in Capella fork
						"blob_gas_used":            "0x0",           // Added in Deneb fork - use hex format for consistency
						"excess_blob_gas":          "0x0",           // Added in Deneb fork - use hex format for consistency
						"parent_beacon_block_root": zeroHash32(),    // Added in Deneb fork
					},

					// Optional for Deneb: blob KZG commitments
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
