package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/adilzuberi/keybroker"
)

const deniedExitCode = 3

type runtimePaths struct {
	audit  string
	socket string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, defaultPaths()))
}

func run(args []string, stdout, stderr io.Writer, paths runtimePaths) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "capabilities":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "keybroker: capabilities takes no arguments")
			return 2
		}
		capabilities, err := keybroker.CapabilitiesUnix(context.Background(), paths.socket)
		if err != nil {
			fmt.Fprintf(stderr, "keybroker: %v\n", err)
			return 1
		}
		return writeJSON(stdout, stderr, capabilities)
	case "check":
		request, ok := parseRequest(args[1:], stderr)
		if !ok {
			return 2
		}
		decision, err := keybroker.CheckUnix(context.Background(), paths.socket, request)
		if err != nil {
			fmt.Fprintf(stderr, "keybroker: %v\n", err)
			return 1
		}
		if exitCode := writeJSON(stdout, stderr, decision); exitCode != 0 {
			return exitCode
		}
		if !decision.Allowed {
			return deniedExitCode
		}
		return 0
	case "invoke":
		request, ok := parseRequest(args[1:], stderr)
		if !ok {
			return 2
		}
		result, err := keybroker.InvokeUnix(context.Background(), paths.socket, request)
		if err != nil {
			fmt.Fprintf(stderr, "keybroker: %v\n", err)
			return 1
		}
		if exitCode := writeJSON(stdout, stderr, result); exitCode != 0 {
			return exitCode
		}
		if !result.Allowed {
			return deniedExitCode
		}
		return 0
	case "serve":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "keybroker: serve takes no arguments")
			return 2
		}
		audit, err := keybroker.NewJSONLAudit(paths.audit)
		if err != nil {
			fmt.Fprintf(stderr, "keybroker: %v\n", err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := keybroker.ServeUnix(ctx, paths.socket, keybroker.NewDefault(audit)); err != nil {
			fmt.Fprintf(stderr, "keybroker: %v\n", err)
			return 1
		}
		return 0
	case "wait":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "keybroker: wait takes no arguments")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := waitForService(ctx, paths.socket); err != nil {
			fmt.Fprintf(stderr, "keybroker: service not ready: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "keybroker: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func parseRequest(args []string, stderr io.Writer) (keybroker.Request, bool) {
	flags := flag.NewFlagSet("request", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return keybroker.Request{}, false
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "keybroker: provide exactly one capability name")
		return keybroker.Request{}, false
	}
	return keybroker.Request{
		Capability: flags.Arg(0),
	}, true
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "keybroker: encode output: %v\n", err)
		return 1
	}
	return 0
}

func defaultPaths() runtimePaths {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return defaultPathsFor(runtime.GOOS, home, os.Getenv("KEYBROKER_AUDIT_LOG"), os.Getenv("KEYBROKER_SOCKET"))
}

func waitForService(ctx context.Context, socketPath string) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := keybroker.CapabilitiesUnix(attempt, socketPath)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func defaultPathsFor(goos, home, audit, socket string) runtimePaths {
	if goos == "linux" {
		if audit == "" {
			audit = "/var/lib/keybroker/audit.jsonl"
		}
		if socket == "" {
			socket = "/run/keybroker/keybroker.sock"
		}
		return runtimePaths{audit: audit, socket: socket}
	}
	if audit == "" {
		audit = filepath.Join(home, "Library", "Logs", "Keybroker", "audit.jsonl")
	}
	if socket == "" {
		socket = filepath.Join(home, "Library", "Application Support", "Keybroker", "keybroker.sock")
	}
	return runtimePaths{audit: audit, socket: socket}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: keybroker <serve|wait|capabilities|check|invoke> [capability]")
}
