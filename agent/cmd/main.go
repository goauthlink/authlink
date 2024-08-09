package main

import (
	"os"

	"github.com/auth-policy-controller/apc/agent/cmd/app"
)

func main() {
	if err := app.NewRootCommand().Execute(); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}
