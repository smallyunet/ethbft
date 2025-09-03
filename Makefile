.PHONY: build run clean test docker-up docker-down docker-rebuild rebuild create-genesis dev-setup

# Project variables
BINARY_NAME=ethbft
MAIN_PKG=./cmd/ethbft

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

all: test build

build:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_PKG)

run: build
	./$(BINARY_NAME)

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf ./cometbft_home
	rm -rf ./geth_data

test:
	$(GOTEST) -v ./...

# Install dependencies
deps:
	$(GOMOD) download

# Generate JWT secret for Engine API authentication
generate-jwt:
	openssl rand -hex 32 > jwt.hex
	@echo "JWT secret generated at jwt.hex"

# Create genesis.json file
create-genesis:
	mkdir -p ./geth_data
	@echo "Creating genesis.json file..."
	@echo '{\n  "config": {\n    "chainId": 1337,\n    "homesteadBlock": 0,\n    "eip150Block": 0,\n    "eip155Block": 0,\n    "eip158Block": 0,\n    "byzantiumBlock": 0,\n    "constantinopleBlock": 0,\n    "petersburgBlock": 0,\n    "istanbulBlock": 0,\n    "berlinBlock": 0,\n    "londonBlock": 0,\n    "mergeForkBlock": 0,\n    "terminalTotalDifficulty": 0\n  },\n  "alloc": {},\n  "difficulty": "1",\n  "gasLimit": "30000000"\n}' > ./geth_data/genesis.json
	@echo "Genesis file created at ./geth_data/genesis.json"

# Start Docker environment
docker-up: generate-jwt create-genesis
	@echo "Starting Docker environment..."
	docker-compose up -d
	@echo "Docker environment started in detached mode"

# Stop Docker environment
docker-down:
	@echo "Stopping Docker environment..."
	docker-compose down
	@echo "Docker environment stopped"

# Rebuild Docker containers
docker-rebuild: docker-down
	@echo "Rebuilding Docker containers..."
	docker-compose build
	@echo "Rebuild complete, starting containers..."
	docker-compose up -d
	
# Alias for docker-rebuild for backward compatibility
rebuild: docker-rebuild

# Development setup
dev-setup: deps generate-jwt create-genesis
	cp config/config.yaml ./
	@echo "Development setup complete"
