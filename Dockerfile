FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy and download dependencies
COPY go.mod ./
# Copy go.sum if it exists
COPY go.sum* ./
RUN go mod tidy && go mod download

# Copy source code
COPY . .

# Build the binary and test tools
RUN CGO_ENABLED=0 GOOS=linux go build -o ethbft ./cmd/ethbft

# Create a minimal production image
FROM alpine:3.17

WORKDIR /app

# Install runtime dependencies (add netcat for docker healthcheck)
RUN apk add --no-cache ca-certificates netcat-openbsd

# Copy binary from builder stage
COPY --from=builder /build/ethbft /app/ethbft
COPY config/docker-config.yaml /app/config.yaml

# Create a non-root user
RUN adduser -D -g '' ethbft
RUN chown -R ethbft:ethbft /app
USER ethbft

# Command to run
CMD ["/app/ethbft"]
