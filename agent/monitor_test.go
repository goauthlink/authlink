package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetHealtHandler(t *testing.T) {
	w := httptest.NewRecorder()

	server := initMonitoringServer(":9191")

	request := httptest.NewRequest(http.MethodGet, "http://localhost:9191/health", nil)

	server.srv.Handler.ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
}
