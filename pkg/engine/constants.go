package engine

import "log"

// Preset enumerations
type Preset string

const (
	PresetMainnet Preset = "mainnet"
	PresetMinimal Preset = "minimal"
)

// Active limits (mutable at init, then treated read-only)
var (
	MAX_TRANSACTIONS_PER_PAYLOAD   uint64
	MAX_WITHDRAWALS_PER_PAYLOAD    uint64
	MAX_PROPOSER_SLASHINGS         uint64
	MAX_ATTESTER_SLASHINGS         uint64
	MAX_ATTESTATIONS               uint64
	MAX_DEPOSITS                   uint64
	MAX_VOLUNTARY_EXITS            uint64
	MAX_BLS_TO_EXECUTION_CHANGES   uint64
	MAX_BLOB_COMMITMENTS_PER_BLOCK uint64
	SYNC_COMMITTEE_SIZE            uint64

	activePreset Preset
)

// applyPreset sets all MAX_* according to chosen preset.
func applyPreset(p Preset) {
	activePreset = p
	switch p {
	case PresetMinimal:
		// Minimal preset (spec reference values)
		MAX_TRANSACTIONS_PER_PAYLOAD = 1 << 20 // keep large to avoid edge constraints during demo
		MAX_WITHDRAWALS_PER_PAYLOAD = 16
		MAX_PROPOSER_SLASHINGS = 16
		MAX_ATTESTER_SLASHINGS = 2
		MAX_ATTESTATIONS = 128
		MAX_DEPOSITS = 16
		MAX_VOLUNTARY_EXITS = 16
		MAX_BLS_TO_EXECUTION_CHANGES = 16
		MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096
		SYNC_COMMITTEE_SIZE = 512
	case PresetMainnet:
		// Mainnet preset (currently same as values we used; differentiate here if future divergence)
		MAX_TRANSACTIONS_PER_PAYLOAD = 1 << 20
		MAX_WITHDRAWALS_PER_PAYLOAD = 16
		MAX_PROPOSER_SLASHINGS = 16
		MAX_ATTESTER_SLASHINGS = 2
		MAX_ATTESTATIONS = 128
		MAX_DEPOSITS = 16
		MAX_VOLUNTARY_EXITS = 16
		MAX_BLS_TO_EXECUTION_CHANGES = 16
		MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096
		SYNC_COMMITTEE_SIZE = 512
	default:
		log.Printf("Unknown preset %s – defaulting to mainnet", p)
		applyPreset(PresetMainnet)
		return
	}
	log.Printf("PRESET: %s | LIMITS: tx=%d withdrawals=%d proposer_slashings=%d attester_slashings=%d attestations=%d deposits=%d voluntary_exits=%d bls_to_exec=%d blob_commitments=%d sync_committee_size=%d",
		p,
		MAX_TRANSACTIONS_PER_PAYLOAD,
		MAX_WITHDRAWALS_PER_PAYLOAD,
		MAX_PROPOSER_SLASHINGS,
		MAX_ATTESTER_SLASHINGS,
		MAX_ATTESTATIONS,
		MAX_DEPOSITS,
		MAX_VOLUNTARY_EXITS,
		MAX_BLS_TO_EXECUTION_CHANGES,
		MAX_BLOB_COMMITMENTS_PER_BLOCK,
		SYNC_COMMITTEE_SIZE,
	)
}

func init() {
	// Default to mainnet unless overridden before Server start (future enhancement could read config)
	applyPreset(PresetMainnet)
}
