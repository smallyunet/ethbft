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
	bridge      *Bridge
	listener    net.Listener
	connections map[string]net.Conn
	mu          sync.Mutex
}

// NewABCIServer creates a new ABCI server
func NewABCIServer(bridge *Bridge) *ABCIServer {
	return &ABCIServer{
		bridge:      bridge,
		connections: make(map[string]net.Conn),
	}
}

// Start starts the ABCI server
func (s *ABCIServer) Start() error {
	addr := s.bridge.config.Bridge.ListenAddr
	log.Printf("Starting ABCI server on %s", addr)

	// Create a simple TCP server for ABCI
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	// Start accepting connections
	go s.acceptConnections()

	// Also start a simple HTTP server for health checks
	go s.startHTTPServer()

	return nil
}

// Stop stops the ABCI server
func (s *ABCIServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, conn := range s.connections {
		conn.Close()
	}
}

// acceptConnections accepts and handles incoming ABCI connections
func (s *ABCIServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			return
		}

		connID := conn.RemoteAddr().String()

		s.mu.Lock()
		s.connections[connID] = conn
		s.mu.Unlock()

		log.Printf("Accepted ABCI connection from %s", connID)

		// Handle the connection in a goroutine
		go s.handleConnection(conn, connID)
	}
}

// handleConnection processes ABCI protocol messages
func (s *ABCIServer) handleConnection(conn net.Conn, connID string) {
	defer func() {
		conn.Close()

		s.mu.Lock()
		delete(s.connections, connID)
		s.mu.Unlock()

		log.Printf("Closed ABCI connection from %s", connID)
	}()

	// This is a simplified placeholder
	// In a real implementation, you would parse ABCI protocol messages here
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Error reading from connection %s: %v", connID, err)
			return
		}

		// Process the ABCI message
		log.Printf("Received %d bytes from %s", n, connID)

		// Echo back a simple response for now
		resp := []byte("OK")
		_, err = conn.Write(resp)
		if err != nil {
			log.Printf("Error writing to connection %s: %v", connID, err)
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
