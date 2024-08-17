package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func WaitSignal(stop chan struct{}) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	stop <- struct{}{}
}
