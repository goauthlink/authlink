// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package observe

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetHealtHandler(t *testing.T) {
	w := httptest.NewRecorder()

	server := NewServer(":9191")

	request := httptest.NewRequest(http.MethodGet, "http://localhost:9191/health", nil)

	server.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
}
