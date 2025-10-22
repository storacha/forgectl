package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/storacha/forgectl/cli/cmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.Execute(ctx); err != nil {
		os.Exit(1)
	}
}
