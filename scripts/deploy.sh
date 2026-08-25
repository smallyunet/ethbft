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
# Generate JWT and Genesis
echo -e "${GREEN}Generating configuration...${NC}"
make generate-jwt
make create-genesis

# Build and Start Docker Containers
echo -e "${GREEN}Starting Docker containers...${NC}"

if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

$DOCKER_COMPOSE up -d --build --remove-orphans

echo -e "${BLUE}Deployment Complete!${NC}"
echo -e "------------------------------------------------"
echo -e "Services are running at:"
echo -e "  - ${GREEN}Geth RPC${NC}:                 http://localhost:8545"
echo -e "  - ${GREEN}CometBFT RPC${NC}:             http://localhost:26657"
echo -e "  - ${GREEN}EthBFT readiness${NC}:         http://localhost:8081/ready"
echo -e "Optional monitoring: docker compose --profile observability up -d"
echo -e "------------------------------------------------"
echo -e "To stop the chain, run: ${BLUE}docker-compose down${NC}"
