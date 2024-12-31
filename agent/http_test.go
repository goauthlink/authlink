// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auth-request-agent/agent/sdk/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initTestHttpServer(t *testing.T, pol *string, cfg *Config, opts ...ServerOpt) (*HttpServer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	fCfg := DefaultConfig()
	if cfg != nil {
		fCfg = *cfg
	}

	srvOptions := []ServerOpt{
		WithLogger(logger),
	}
	srvOptions = append(srvOptions, opts...)

	var checker *policy.Checker
	if pol != nil {
		checker = policy.NewChecker()
		require.NoError(t, checker.SetPolicy([]byte(*pol)))
	}
	policy := NewPolicy(checker, nil, nil)

	httpServer, err := NewHttpServer(fCfg.HttpAddr, policy, srvOptions...)
	require.NoError(t, err)

	return httpServer, buf
}

func Test_HTTPMethodCharCase(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["/ep2"]
    method: ["POST"]
    allow: ["client1"]`

	w := httptest.NewRecorder()

	httpServer, logs := initTestHttpServer(t, &config, nil)

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/check", nil)
	request.Header.Set("x-path", "/ep1")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client1")

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code, logs)

	// --
	request.Header.Set("x-method", "get")

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code, logs)

	// --
	request.Header.Set("x-path", "/ep2")
	request.Header.Set("x-method", "POST")

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code, logs)

	// --
	request.Header.Set("x-path", "/ep2")
	request.Header.Set("x-method", "post")

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code, logs)
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

	httpServer.httpserver.Handler.ServeHTTP(w, request)

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

	httpServer.httpserver.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusForbidden, w.Code, logs)
}
