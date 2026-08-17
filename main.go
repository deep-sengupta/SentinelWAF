package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sentinelwaf/internal/config"
	"sentinelwaf/internal/logging"
	"sentinelwaf/internal/state"
	"sentinelwaf/internal/waf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]
	flags := flag.NewFlagSet(mode, flag.ExitOnError)
	configPath := flags.String("config", "config/config.json", "configuration file")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stateStore := state.New(cfg.ResolvePath(cfg.Runtime.StateFile))
	if err := stateStore.Ensure(true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	auditor := logging.New(cfg.ResolvePath(cfg.Runtime.LogFile))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch mode {
	case "waf":
		server, err := waf.NewServer(cfg, auditor, stateStore)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := server.Start(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: sentinelwaf waf -config config/config.json")
}
