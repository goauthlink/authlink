package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/auth-policy-controller/apc/pkg/policy"
)

type httpServer struct {
	srv *http.Server
}

func initHttpServer(config Config, logger *slog.Logger, checker *policy.Checker) *httpServer {
	router := http.NewServeMux()
	router.Handle("GET /healtz", routerGetHealtzHandler())
	router.Handle("POST /check", routerPostCheckHandler(logger, checker))

	httpSrv := &httpServer{
		srv: &http.Server{
			Addr:    config.Addr,
			Handler: router,
		},
	}

	return httpSrv
}

func (httpServer *httpServer) serve() error {
	err := httpServer.srv.ListenAndServe()
	if err != nil {
		return fmt.Errorf("http server listening: %w", err)
	}

	return nil
}

func (httpServer *httpServer) shutdown(ctx context.Context) error {
	ctxd, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	err := httpServer.srv.Shutdown(ctxd)
	if err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	return nil
}

func routerGetHealtzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func routerPostCheckHandler(logger *slog.Logger, checker *policy.Checker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := policy.CheckInput{
			Uri:     r.Header.Get("x-path"), // todo: move to setting
			Method:  r.Header.Get("x-method"),
			Headers: map[string]string{},
		}

		for key, headerVal := range r.Header {
			in.Headers[strings.ToLower(key)] = strings.Join(headerVal, ",")
		}

		// todo: allow_on_err

		allow, err := checker.Check(in)
		if err != nil {
			logger.Error(fmt.Sprintf("http check failed: %s", err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}
