// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

func isLabelsMatched(labels, need map[string]string) bool {
	for nname, nvalue := range need {
		if itemValue, exists := labels[nname]; !exists || itemValue != nvalue {
			return false
		}
	}

	return true
}
