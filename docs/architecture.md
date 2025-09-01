# EthBFT Architecture Guide

This document describes the architecture of EthBFT, a bridge layer between Ethereum execution clients and CometBFT consensus.

## Overview

EthBFT is designed as a simple bridge layer that connects Ethereum's execution capabilities with CometBFT's consensus mechanism. The goal is to provide a minimal but functional interface between these two systems without unnecessary complexity.

```
┌──────────────┐     ┌───────────┐     ┌───────────┐
│  Ethereum    │     │           │     │           │
│  Execution   │◄───►│  EthBFT   │◄───►│ CometBFT  │
│  Client      │     │  Bridge   │     │           │
└──────────────┘     └───────────┘     └───────────┘
```

## Components

### Ethereum Client Module (`pkg/ethereum`)

This module provides an interface to communicate with Ethereum execution clients via their JSON-RPC API. Key features:

- Connection to standard Ethereum JSON-RPC API
- Support for the Engine API (post-merge)
- Block retrieval and submission
- JWT authentication for Engine API

### CometBFT Consensus Module (`pkg/consensus`)

This module interfaces with CometBFT's RPC API. Key features:

- Connection to CometBFT RPC endpoints
- Block proposal and transaction broadcasting
- Status monitoring

### Bridge Module (`pkg/bridge`)

This module acts as the central component connecting Ethereum and CometBFT. Key features:

- Converts Ethereum block data to CometBFT-compatible format
- Relays blocks between systems
- Handles the main processing loop
- Simple state management

### Configuration Module (`pkg/config`)

This module handles configuration loading and validation. Key features:

- Default configuration values
- Configuration file loading
- Environment variable support

### Types Module (`pkg/types`)

This module provides shared data structures and type definitions used across the application. Key features:

- Ethereum block and transaction structures
- CometBFT block and transaction structures
- Bridge-specific data structures

## Processing Flow

1. The bridge fetches the latest block from the Ethereum execution client
2. The block data is transformed into a format compatible with CometBFT
3. The transformed block is proposed to CometBFT for consensus
4. Once consensus is reached, the finalized block information is relayed back to the Ethereum execution client
5. This process repeats for each new block

## Design Principles

1. **Simplicity**: Keep the codebase as simple as possible, focusing on core functionality
2. **Minimal State**: Avoid complex state management; rely on Ethereum and CometBFT for state
3. **Modularity**: Design components with clear interfaces that can be tested independently
4. **Tool-oriented**: Focus on being a utility that connects existing systems rather than a complex application

## Configuration Options

Configuration is managed through a JSON file with the following main sections:

- **Ethereum**: Connection details for the Ethereum execution client
- **CometBFT**: Connection details for the CometBFT node
- **Bridge**: Settings for the bridge component itself
