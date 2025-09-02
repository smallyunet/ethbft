package bridge

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

// ABCIServer represents a server that implements the ABCI protocol
type ABCIServer struct {
	bridge    *Bridge
	listener  net.Listener
	mu        sync.Mutex
	isRunning bool
}

// NewABCIServer creates a new ABCI server
func NewABCIServer(bridge *Bridge) *ABCIServer {
	return &ABCIServer{
		bridge: bridge,
	}
}

// Start starts the ABCI server
func (s *ABCIServer) Start() error {
	addr := s.bridge.config.Bridge.ListenAddr
	log.Printf("Starting gRPC ABCI server on %s", addr)

	var err error
	// Create a TCP listener for the gRPC ABCI server
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.isRunning = true

	// Handle connections
	go s.acceptConnections()

	// Also start a simple HTTP server for health checks
	go s.startHTTPServer()

	return nil
}

// Stop stops the ABCI server
func (s *ABCIServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}
	s.isRunning = false
}

// acceptConnections accepts and handles incoming ABCI connections
func (s *ABCIServer) acceptConnections() {
	for s.isRunning {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isRunning {
				log.Printf("Error accepting connection: %v", err)
			}
			return
		}

		log.Printf("Accepted ABCI connection from %s", conn.RemoteAddr().String())

		// Handle the connection in a goroutine
		go s.handleABCIConnection(conn)
	}
}

// handleABCIConnection handles an ABCI connection using gRPC protocol
func (s *ABCIServer) handleABCIConnection(conn net.Conn) {
	defer conn.Close()

	// In a real implementation, we would use the gRPC protocol here
	// This is a simplified version that responds to ABCI requests
	// with predefined responses to make CometBFT happy

	buffer := make([]byte, 4096)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return
		}

		// Here we should properly decode and handle the gRPC requests
		// For now, we're just acknowledging receipt
		log.Printf("Received %d bytes from ABCI client", n)

		// Send a simple response
		// In a real implementation, we would encode proper gRPC responses
		response := []byte("OK\n")
		_, err = conn.Write(response)
		if err != nil {
			log.Printf("Error writing to connection: %v", err)
			return
		}
	}
}

// startHTTPServer starts a simple HTTP server for health checks
func (s *ABCIServer) startHTTPServer() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Listen on a different port for HTTP
	httpAddr := "0.0.0.0:8081"
	log.Printf("Starting HTTP health check server on %s", httpAddr)
	err := http.ListenAndServe(httpAddr, nil)
	if err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}
