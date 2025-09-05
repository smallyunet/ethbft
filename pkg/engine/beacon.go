package engine

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// Beacon API router

func (s *Server) handleBeaconAPI(w http.ResponseWriter, r *http.Request) {
	log.Printf("Beacon API request: %s %s", r.Method, r.URL.Path)

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle OPTIONS requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Readiness gate: all Beacon API endpoints return 503 until system ready
	if !s.isReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "service not ready"})
		return
	}

	// Handle different Beacon API endpoints (only reached when ready)
	switch {
	case r.URL.Path == "/eth/v1/events":
		// Handle events stream - this is what geth needs for consensus updates
		s.handleEventsStream(w, r)
	case r.URL.Path == "/eth/v1/beacon/headers/head":
		// Return current head header
		s.handleHeadHeader(w, r)
	case r.URL.Path == "/eth/v1/beacon/state":
		// Return beacon state
		s.handleBeaconState(w, r)
	case r.URL.Path == "/eth/v1/beacon/forks":
		// Return fork information
		s.handleBeaconForks(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/light_client/bootstrap/"):
		// Return light client bootstrap
		s.handleLightClientBootstrap(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/blocks/"):
		// Return beacon block
		s.handleBeaconBlock(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/headers/"):
		// Return beacon header
		s.handleBeaconHeader(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v2/beacon/blocks/"):
		// Return beacon block v2
		s.handleBeaconBlockV2(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v2/beacon/headers/"):
		// Return beacon header v2
		s.handleBeaconHeaderV2(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/genesis"):
		// Return genesis information
		s.handleBeaconGenesis(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/validators/"):
		// Return validator information
		s.handleBeaconValidators(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/checkpoint"):
		// Return checkpoint information
		s.handleBeaconCheckpoint(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/sync_committees"):
		// Return sync committees information
		s.handleBeaconSyncCommittees(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/state/"):
		// Return beacon state by state ID
		s.handleBeaconStateByState(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/light_client/updates"):
		// Return light client updates
		s.handleLightClientUpdates(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/light_client/finality_update"):
		// Return light client finality update
		s.handleLightClientFinalityUpdate(w, r)
	case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/light_client/optimistic_update"):
		// Return light client optimistic update
		s.handleLightClientOptimisticUpdate(w, r)
	default:
		// For other endpoints, return a simple response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"execution_optimistic": false,
				"finalized":            false,
			},
		})
	}
}
