package envoy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/auth-request-agent/agent/agent"
	"github.com/auth-request-agent/agent/sdk/policy"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rpc_code "google.golang.org/genproto/googleapis/rpc/code"
)

func newTestServer(t *testing.T, pol string) *Server {
	checker := policy.NewChecker()
	require.NoError(t, checker.SetPolicy([]byte(pol)))

	policy := agent.NewPolicy(checker, nil, nil)
	srv, err := New(":0", policy)
	require.NoError(t, err)

	return srv
}

var envoyRequest = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "",
		  "method": "GET",
		  "headers": {
			":authority": "192.168.0.100:9080",
			":method": "GET",
			":path": "/endpoint",
			"accept": "*/*",
			"content-length": "0",
			"user-agent": "curl/8.6.0",
			"x-source": "client1",
			"x-envoy-internal": "true",
			"x-forwarded-for": "172.17.0.1",
			"x-forwarded-proto": "http",
			"x-request-id": "b116822d-11ce-4124-aa76-7f5ed10d6f22"
		  },
		  "path": "/endpoint",
		  "host": "192.168.0.100:9080",
		  "protocol": "HTTP/1.1",
		  "body": "{}"
		}
	  }
	}
  }`

func Test_CheckAllow(t *testing.T) {
	pol := `
cn:
  - header: "x-source"
policies:
  - uri: ["/endpoint"]
    allow: ["client1"]`

	srv := newTestServer(t, pol)

	var req authv3.CheckRequest
	require.NoError(t, json.Unmarshal([]byte(envoyRequest), &req))

	out, err := srv.Check(context.Background(), &req)
	require.NoError(t, err)

	assert.Equal(t, int32(rpc_code.Code_OK), out.Status.Code)
}

func Test_CheckDenied(t *testing.T) {
	pol := `
cn:
  - header: "x-source"
policies:
  - uri: ["/endpoint"]
    allow: ["client2"]`

	srv := newTestServer(t, pol)

	var req authv3.CheckRequest
	require.NoError(t, json.Unmarshal([]byte(envoyRequest), &req))

	out, err := srv.Check(context.Background(), &req)
	require.NoError(t, err)

	assert.Equal(t, int32(rpc_code.Code_PERMISSION_DENIED), out.Status.Code)
}
