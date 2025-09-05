package engine

// genesisExecutionPayload returns the canonical genesis (block 0) execution payload
// with all fields mapped exactly as required in Step 1 specification:
// parent_hash = 0x00..00 (Root)
// fee_recipient = 20 zero bytes (Address)
// state_root = mainnet genesis state root (from JSON stateRoot)
// receipts_root = mainnet genesis receipts root (from JSON receiptsRoot)
// logs_bloom = 256 zero bytes (ByteVector[256])
// prev_randao = 0x00..00
// block_number = 0
// gas_limit = 0x1388 (from JSON gasLimit)
// gas_used = 0
// timestamp = 0
// extra_data = JSON extraData (ByteList[32] – length mixed in via SSZ)
// base_fee_per_gas = 0
// block_hash = mainnet genesis hash (from JSON hash)
// transactions = [] (List<ByteList>)
// withdrawals = [] (List<Withdrawal>)
// blob_gas_used = 0
// excess_blob_gas = 0
// parent_beacon_block_root = 0 (post-Deneb field kept zero for demo)
func genesisExecutionPayload() *ExecutionPayload {
	return &ExecutionPayload{
		ParentHash:            zeroHash32(),
		FeeRecipient:          zeroHexBytes(20),
		StateRoot:             "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
		ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		LogsBloom:             zeroBloom256(),
		PrevRandao:            zeroHash32(),
		BlockNumber:           "0x0",
		GasLimit:              "0x1388",
		GasUsed:               "0x0",
		Timestamp:             "0x0",
		ExtraData:             "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa", // 32 bytes
		BaseFeePerGas:         "0x0",
		BlockHash:             "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		Transactions:          []string{},
		Withdrawals:           []string{},
		BlobGasUsed:           "0x0",
		ExcessBlobGas:         "0x0",
		ParentBeaconBlockRoot: zeroHash32(),
	}
}
