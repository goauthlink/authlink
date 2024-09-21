// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auth-request-agent/agent/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testMetrics struct{}

func (tm *testMetrics) CheckRqTotalInc(ctx context.Context)                  {}
func (tm *testMetrics) CheckRqFailedInc(ctx context.Context)                 {}
func (tm *testMetrics) CheckRqDurationObserve(ctx context.Context, ms int64) {}

func initTestHttpServer(t *testing.T, pol *string, config *Config, opts ...httpServerOpt) (*httpServer, *bytes.Buffer) {
	var checker *policy.Checker
	if pol != nil {
		checker = policy.NewChecker()
		require.NoError(t, checker.SetPolicy([]byte(*pol)))
	}

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	fCfg := DefaultConfig()
	if config != nil {
		fCfg = *config
	}

	srvOptions := []httpServerOpt{
		withLogger(logger),
		withChecker(checker),
		withMetrics(&testMetrics{}),
	}
	srvOptions = append(srvOptions, opts...)

	httpServer, err := initHttpServer(fCfg.Addr, srvOptions...)
	require.NoError(t, err)

	return httpServer, buf
}

func Test_CheckAllowHandler(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1/sub1"]
    allow: ["client1"]`

	w := httptest.NewRecorder()

	httpServer, logs := initTestHttpServer(t, &config, nil)

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/check", nil)
	request.Header.Set("x-path", "/ep1/sub1")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client1")

	httpServer.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code, logs)
}

func Test_CheckDeniedHandler(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1/sub1"]
    allow: ["client1"]`

	w := httptest.NewRecorder()

	httpServer, logs := initTestHttpServer(t, &config, nil)

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/check", nil)
	request.Header.Set("x-path", "/ep1/sub1")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client2")

	httpServer.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusForbidden, w.Code, logs)
}
