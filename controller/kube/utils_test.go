// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import "testing"

func Test_IsLabelsMatched(t *testing.T) {
	if !isLabelsMatched(map[string]string{"l2": "v2", "l1": "v1"}, map[string]string{"l1": "v1"}) {
		t.Error("labels are not matched")
	}

	if isLabelsMatched(map[string]string{"l1": "v1", "l2": "v2"}, map[string]string{"l3": "v3", "l1": "v1"}) {
		t.Error("labels are matched")
	}

	if isLabelsMatched(map[string]string{"l2": "v2", "l1": "v1"}, map[string]string{"l1": "v2"}) {
		t.Error("labels are matched")
	}

	if !isLabelsMatched(map[string]string{}, map[string]string{}) {
		t.Error("labels are not matched")
	}
}
