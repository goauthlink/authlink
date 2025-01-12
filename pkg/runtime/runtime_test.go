// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package runtime

import (
	"context"
	"sync"
	"testing"

	"github.com/goauthlink/authlink/pkg/logging"
	"github.com/stretchr/testify/require"
)

type testServer struct{}

func (ts *testServer) Name() string {
	return "test-server"
}

func (ts testServer) Start(_ context.Context) error {
	return nil
}

func (ts testServer) Shutdown(_ context.Context) error {
	return nil
}

func Test_Runtime(t *testing.T) {
	logger := logging.NewNullLogger()
	runtime := NewRuntime([]Server{
		&testServer{},
		&testServer{},
	}, logger)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := runtime.Start()
		wg.Done()
		require.NoError(t, err)
	}()

	runtime.Stop()

	wg.Wait()
}
