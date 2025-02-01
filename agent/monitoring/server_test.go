// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package monitoring

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_GetHealtHandler(t *testing.T) {
	w := httptest.NewRecorder()

	server, err := NewServer(":9191")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://localhost:9191/health", nil)

	server.srv.Handler.ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected status, got %v", w.Code)
	}
}
