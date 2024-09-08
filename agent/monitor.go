package agent

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type monitoringServer struct {
	srv *http.Server
}

func initMonitoringServer(addr string) *monitoringServer {
	router := http.NewServeMux()
	router.Handle("GET /stats/prometheus", promhttp.Handler())
	router.Handle("GET /health", routerGetHealtzHandler())

	monitoringSrv := &monitoringServer{
		srv: &http.Server{
			Addr:    addr,
			Handler: router,
		},
	}

	return monitoringSrv
}

func routerGetHealtzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (monitorSrv *monitoringServer) serve() error {
	err := monitorSrv.srv.ListenAndServe()
	if err != nil {
		return fmt.Errorf("monitoring server listening: %w", err)
	}

	return nil
}

func (monitorSrv *monitoringServer) shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	err := monitorSrv.srv.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown monitoring server: %w", err)
	}

	return nil
}
