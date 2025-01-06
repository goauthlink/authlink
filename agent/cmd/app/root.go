// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package app

import (
	"os"
	"path"

	"github.com/spf13/cobra"
)

func NewRootCommand(runExtensions ...RunExtension) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   path.Base(os.Args[0]),
		Short: "Auth policy agent",
	}

	rootCmd.AddCommand(newRunCmd(runExtensions...))
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}
