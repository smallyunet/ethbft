.PHONY: all build run clean test lint check test-e2e test-e2e-fast test-multinode-e2e test-multinode-e2e-fast deploy docker-up docker-down docker-rebuild generate-jwt create-genesis deps

BINARY_NAME=ethbft

all: check build

build:
	cargo build --release --locked
	cp target/release/$(BINARY_NAME) ./$(BINARY_NAME)

run:
	cargo run --locked

clean:
	cargo clean
	rm -f $(BINARY_NAME)
	rm -rf ./cometbft_home ./geth_data

test:
	cargo test --locked --all-targets

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

check: lint test

test-e2e:
	ETHBFT_E2E=1 cargo test --locked --test e2e -- --nocapture

test-e2e-fast:
	ETHBFT_E2E=1 ETHBFT_E2E_NO_BUILD=1 cargo test --locked --test e2e -- --nocapture

test-multinode-e2e:
	ETHBFT_MULTINODE_E2E=1 cargo test --locked --test multinode_e2e -- --nocapture

test-multinode-e2e-fast:
	ETHBFT_MULTINODE_E2E=1 ETHBFT_MULTINODE_E2E_NO_BUILD=1 cargo test --locked --test multinode_e2e -- --nocapture

deploy:
	./scripts/deploy.sh

deps:
	cargo fetch --locked

generate-jwt:
	@if [ ! -f jwt.hex ]; then \
		printf "%s" "$$(openssl rand -hex 32)" > jwt.hex; \
		echo "JWT secret generated at jwt.hex"; \
	else \
		echo "JWT secret already exists at jwt.hex, skipping"; \
	fi

create-genesis:
	mkdir -p ./geth_data
	@echo "Creating genesis.json file..."
	@echo '{\n  "config": {\n    "chainId": 1337,\n    "homesteadBlock": 0,\n    "eip150Block": 0,\n    "eip155Block": 0,\n    "eip158Block": 0,\n    "byzantiumBlock": 0,\n    "constantinopleBlock": 0,\n    "petersburgBlock": 0,\n    "istanbulBlock": 0,\n    "berlinBlock": 0,\n    "londonBlock": 0,\n    "terminalTotalDifficulty": 0,\n    "shanghaiTime": 0\n  },\n  "alloc": {},\n  "difficulty": "1",\n  "gasLimit": "30000000"\n}' > ./geth_data/genesis.json

docker-up: generate-jwt create-genesis
	docker compose up -d

docker-down:
	docker compose down

docker-rebuild: docker-down generate-jwt create-genesis
	docker compose build
	docker compose up -d
