package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/goauthlink/authlink/controller"
)

func exitErr(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func main() {
	contorller, err := controller.Init(controller.Config{
		Addr:          ":8181",
		LogLevel:      slog.LevelDebug,
		DiscoveryAddr: "",
		Kubeconfig:    ".dev/kubeconfig",
	})
	if err != nil {
		panic(err)
	}

	contorller.Start()
}
