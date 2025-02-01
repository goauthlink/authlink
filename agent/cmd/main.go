// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"

	"github.com/goauthlink/authlink/agent/cmd/run"
)

func main() {
	if err := run.RunCmd(os.Args, []run.AgentRunExt{}); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
