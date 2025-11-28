#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting EthBFT Deployment...${NC}"

# Check dependencies
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed."
    exit 1
fi
if ! command -v go &> /dev/null; then
    echo "Error: go is not installed."
    exit 1
fi

# Build EthBFT binary (for local usage/verification)
echo -e "${GREEN}Building EthBFT binary...${NC}"
make build

# Generate JWT and Genesis
echo -e "${GREEN}Generating configuration...${NC}"
make generate-jwt
make create-genesis

# Build and Start Docker Containers
echo -e "${GREEN}Starting Docker containers...${NC}"
docker-compose up -d --build --remove-orphans

echo -e "${BLUE}Deployment Complete!${NC}"
echo -e "------------------------------------------------"
echo -e "Services are running at:"
echo -e "  - ${GREEN}Block Explorer (Alethio)${NC}:   http://localhost:5100"
echo -e "  - ${GREEN}Monitoring (Grafana)${NC}:     http://localhost:3000 (user: admin, pass: admin)"
echo -e "  - ${GREEN}Prometheus${NC}:               http://localhost:9093"
echo -e "  - ${GREEN}Geth RPC${NC}:                 http://localhost:8545"
echo -e "  - ${GREEN}CometBFT RPC${NC}:             http://localhost:26657"
echo -e "------------------------------------------------"
echo -e "To stop the chain, run: ${BLUE}docker-compose down${NC}"
