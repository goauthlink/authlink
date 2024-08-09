package agent

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auth-policy-controller/apc/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initTestHttpServer(t *testing.T, pol *string) (*httpServer, *bytes.Buffer) {
	var checker *policy.Checker
	if pol != nil {
		prepCfg, err := policy.PrepareConfig([]byte(*pol))
		require.NoError(t, err)
		checker = policy.NewChecker(prepCfg)
	}

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	httpServer := initHttpServer(Config{
		Addr: ":8080",
	}, logger, checker)

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

	httpServer, logs := initTestHttpServer(t, &config)

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

	httpServer, logs := initTestHttpServer(t, &config)

	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/check", nil)
	request.Header.Set("x-path", "/ep1/sub1")
	request.Header.Set("x-method", "GET")
	request.Header.Set("x-source", "client2")

	httpServer.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusForbidden, w.Code, logs)
}

func Test_GetHealtzHandler(t *testing.T) {
	w := httptest.NewRecorder()

	httpServer, _ := initTestHttpServer(t, nil)

	request := httptest.NewRequest(http.MethodGet, "http://localhost:8080/healtz", nil)

	httpServer.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
}
