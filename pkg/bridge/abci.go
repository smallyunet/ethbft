package bridge

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	abciserver "github.com/cometbft/cometbft/abci/server"
	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// ABCIServer 使用官方 socket server，而不是自定义 TCP/HTTP
type ABCIServer struct {
	bridge *Bridge
	srv    interface {
		Start() error
		Stop() error
	}
	httpServer *http.Server
	listenAddr string // e.g. "0.0.0.0:8080"
	healthAddr string // e.g. "0.0.0.0:8081"
}

func NewABCIServer(bridge *Bridge) *ABCIServer {
	addr := "0.0.0.0:8080"
	health := "0.0.0.0:8081"
	if bridge.config != nil {
		if bridge.config.Bridge.ListenAddr != "" {
			addr = bridge.config.Bridge.ListenAddr
		}
		// 如果你有专门的健康检查端口配置，可在这里读取
	}
	return &ABCIServer{
		bridge:     bridge,
		listenAddr: addr,
		healthAddr: health,
	}
}

func (s *ABCIServer) Start() error {
	log.Printf("Starting ABCI socket server on %s", s.listenAddr)

	// 你的业务 ABCI 应用（最小可用，下面实现了握手必要的方法）
	app := NewABCIApp(s.bridge)

	// 使用官方 socket server（"socket"），自动支持四条连接（query/snapshot/mempool/consensus）
	srv, err := abciserver.NewServer(s.listenAddr, "socket", app)
	if err != nil {
		return fmt.Errorf("failed to create ABCI socket server on %s: %w", s.listenAddr, err)
	}
	s.srv = srv

	// 启动健康检查 HTTP（独立端口，避免与 ABCI socket 混淆）
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	s.httpServer = &http.Server{
		Addr:              s.healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	go func() {
		ln, err := net.Listen("tcp", s.healthAddr)
		if err != nil {
			log.Printf("health server listen error: %v", err)
			return
		}
		log.Printf("Starting HTTP health check server on %s", s.healthAddr)
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("health server error: %v", err)
		}
	}()

	// 启动 ABCI socket
	if err := s.srv.Start(); err != nil {
		return fmt.Errorf("failed to start ABCI socket server: %w", err)
	}
	return nil
}

func (s *ABCIServer) Stop() {
	if s.srv != nil {
		_ = s.srv.Stop()
	}
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
	}
}

/* ===================== 最小可用的 ABCI 应用 ===================== */

type ABCIApp struct {
	abcitypes.BaseApplication // 提供默认实现，避免一次性实现所有方法
	bridge                    *Bridge
}

func NewABCIApp(b *Bridge) *ABCIApp { return &ABCIApp{bridge: b} }

// Echo：常用自检
func (a *ABCIApp) Echo(ctx context.Context, req *abcitypes.RequestEcho) (*abcitypes.ResponseEcho, error) {
	return &abcitypes.ResponseEcho{Message: req.Message}, nil
}

// Info：握手必须返回
func (a *ABCIApp) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	return &abcitypes.ResponseInfo{
		Version:         "ethbft-0.1.0",
		AppVersion:      1,
		LastBlockHeight: 0, // 初次启动为 0，后续可从持久化恢复
		// LastBlockAppHash: 可按需填
	}, nil
}

// InitChain：首次启动必须响应（可在此初始化状态/验证人等）
func (a *ABCIApp) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	return &abcitypes.ResponseInitChain{}, nil
}

// 以下是最小化通过的实现；后续你可以把真实业务逻辑填进去
func (a *ABCIApp) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	return &abcitypes.ResponseCheckTx{Code: 0}, nil
}
func (a *ABCIApp) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	return &abcitypes.ResponseFinalizeBlock{}, nil
}
func (a *ABCIApp) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	// TODO: 返回真实 app hash；先空返回也能让节点进入工作流
	return &abcitypes.ResponseCommit{}, nil
}
