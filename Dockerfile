FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy and download dependencies
COPY go.mod ./
# Copy go.sum if it exists
COPY go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary and test tools
RUN CGO_ENABLED=0 GOOS=linux go build -o ethbft ./cmd/ethbft

# Create a minimal production image
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

WORKDIR /app

# Install runtime dependencies (add netcat for docker healthcheck)
RUN apk add --no-cache ca-certificates netcat-openbsd

# Copy binary from builder stage
COPY --from=builder /build/ethbft /app/ethbft
COPY config/docker-config.yaml /app/config.yaml

# Create a non-root user
RUN adduser -D -g '' ethbft
RUN mkdir -p /app/data
RUN chown -R ethbft:ethbft /app
USER ethbft

# Command to run
CMD ["/app/ethbft"]
