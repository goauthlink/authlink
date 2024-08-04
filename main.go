package main

import (
	"os"

	"github.com/auth-policy-controller/apc/cmd"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}
