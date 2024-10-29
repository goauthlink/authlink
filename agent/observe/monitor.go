package observe

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	srv    *http.Server
	logger *slog.Logger
}

type ServerOpt func(*Server)

func WithLogger(logger *slog.Logger) ServerOpt {
	return func(s *Server) {
		s.logger = logger
	}
}

func NewServer(addr string, opts ...ServerOpt) *Server {
	router := http.NewServeMux()
	router.Handle("GET /stats/prometheus", promhttp.Handler())
	router.Handle("GET /health", routerGetHealtzHandler())

	monitoringSrv := &Server{
		srv: &http.Server{
			Addr:    addr,
			Handler: router,
		},
	}

	for _, o := range opts {
		o(monitoringSrv)
	}

	return monitoringSrv
}

func routerGetHealtzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (monitorSrv *Server) Serve() error {
	err := monitorSrv.srv.ListenAndServe()
	monitorSrv.logger.Info("monitor server is starting..")
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("monitoring server listening: %w", err)
	}

	return nil
}

func (monitorSrv *Server) Shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := monitorSrv.srv.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown monitoring server: %w", err)
	}

	monitorSrv.logger.Info("monitor server stopped")

	return nil
}
