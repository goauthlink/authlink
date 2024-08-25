// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package app

import (
	"fmt"

	"github.com/auth-policy-controller/apc/pkg"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show apc version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(pkg.Version)
		},
	}
}
