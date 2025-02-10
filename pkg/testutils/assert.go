// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package testutils

import (
	"strings"
	"testing"
)

func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no error; got %s", err)
	}
}

// assertError confirms that the provided is an error having the provided message.
func AssertErrorContains(t *testing.T, err error, containing string) {
	if err == nil {
		t.Fatalf("expected error containing '%s' but got nothing", containing)
	}
	if !strings.Contains(err.Error(), containing) {
		t.Fatalf("expected error to contain '%s' but got '%s'", containing, err.Error())
	}
}
