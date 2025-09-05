package engine

// beaconHeaderFields holds minimal fields to compute a pseudo SSZ root for BeaconBlockHeader.
type beaconHeaderFields struct {
	Slot       int64
	ParentRoot string
	StateRoot  string
	BodyRoot   string
}

// BeaconBlockBody represents the 12 Deneb body fields (simplified: all empty except execution_payload)
type BeaconBlockBody struct {
	RandaoReveal           [96]byte // stored as 96 raw bytes (all zero)
	Eth1DepositRoot        [32]byte
	Eth1DepositCount       uint64
	Eth1BlockHash          [32]byte
	Graffiti               [32]byte
	ProposerSlashings      [][]byte
	AttesterSlashings      [][]byte
	Attestations           [][]byte
	Deposits               [][]byte
	VoluntaryExits         [][]byte
	SyncCommitteeBits      [64]byte // 512 bits
	SyncCommitteeSignature [96]byte
	ExecutionPayload       *ExecutionPayload
	BLSToExecutionChanges  [][]byte
	BlobKZGCommitments     [][]byte
}

// BeaconBlock (unsigned)
type BeaconBlock struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	Body          *BeaconBlockBody
}

// SignedBeaconBlock (signature always zero for mock)
type SignedBeaconBlock struct {
	Message   *BeaconBlock
	Signature [96]byte
}

// Real SSZ container wrappers (hash-only) leveraging github.com/karalabe/ssz
type SignedBeaconBlockContainer struct {
	Message   *BeaconBlockContainer
	Signature [96]byte
}

type BeaconBlockContainer struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte
	StateRoot     [32]byte
	Body          *BeaconBlockBodyContainer
}

type BeaconBlockBodyContainer struct {
	Payload *ExecutionPayload
}

// BeaconBlockBodyWithRealPayload represents a Deneb beacon block body with complete execution payload
type BeaconBlockBodyWithRealPayload struct {
	ExecutionPayload *ExecutionPayload
}

// BeaconBlockBodyDeneb represents a Deneb beacon block body for SSZ computation
type BeaconBlockBodyDeneb struct {
	StateRoot   string
	BlockNumber uint64
	Timestamp   uint64
}

// BeaconHeaderSSZ represents a beacon block header for SSZ computation
type BeaconHeaderSSZ struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	BodyRoot      string
}

// BLSSignature represents a 96-byte BLS signature
type BLSSignature struct {
	Data [96]byte
}

// Bytes32 represents a 32-byte value
type Bytes32 struct {
	Data [32]byte
}

// Eth1Data represents Ethereum 1.0 data
type Eth1Data struct {
	DepositRoot  string
	DepositCount uint64
	BlockHash    string
}

// Empty list structures
type ProposerSlashingsList struct{}
type AttesterSlashingsList struct{}
type AttestationsList struct{}
type DepositsList struct{}
type VoluntaryExitsList struct{}
type BLSToExecutionChangesList struct{}
type BlobKZGCommitmentsList struct{}

// SyncAggregate represents sync committee aggregate
type SyncAggregate struct {
	SyncCommitteeBits      []byte
	SyncCommitteeSignature *BLSSignature
}

// ExecutionPayloadSSZ wraps ExecutionPayload for SSZ
type ExecutionPayloadSSZ struct {
	Payload *ExecutionPayload
}

// BeaconBlockBodyCheck - SSZ body structure for self-check
type BeaconBlockBodyCheck struct {
	Payload *ExecutionPayload
}

// BeaconBlockCheck - SSZ block container for self-check; its root should match header root we export
type BeaconBlockCheck struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	Body          *BeaconBlockBodyCheck
}
