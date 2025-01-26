// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package models

type LabelSet map[string]string

type Policy struct {
	Name      string
	Namespace string
	Raw       []byte
	Labels    LabelSet
}
