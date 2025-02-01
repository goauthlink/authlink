// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package models

import (
	"github.com/goauthlink/authlink/sdk/policy"
)

type LabelSet map[string]string

type Policy struct {
	Name      string
	Namespace string
	Config    policy.Config
	Labels    LabelSet
}
