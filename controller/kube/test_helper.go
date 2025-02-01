// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package kube

import (
	"log/slog"

	"github.com/goauthlink/authlink/controller/apis/generated/clientset/versioned/fake"
)

func NewFakeApi(logger *slog.Logger) (*Api, *fake.Clientset) {
	clientSet := fake.NewSimpleClientset()

	return initApi(clientSet, logger), clientSet
}
