package main

import (
	"os"

	"github.com/auth-request-agent/agent/agent/cmd/app"
)

func main() {
	if err := app.NewRootCommand(NewEnvoyExtension()).Execute(); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}
