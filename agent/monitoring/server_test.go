// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package monitoring

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetHealtHandler(t *testing.T) {
	w := httptest.NewRecorder()

	server, err := NewServer(":9191")
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodGet, "http://localhost:9191/health", nil)

	server.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
}
