// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"os"

	"github.com/goauthlink/authlink/agent/cmd/app"
)

func main() {
	if err := app.NewRootCommand().Execute(); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}
