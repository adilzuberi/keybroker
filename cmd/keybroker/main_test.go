package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adilzuberi/keybroker"
)

func TestCapabilitiesCommandPrintsMachineReadablePolicySurface(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	paths := startTestService(t)

	exitCode := run(
		[]string{"capabilities"},
		&stdout,
		&stderr,
		paths,
	)

	if exitCode != 0 {
		t.Fatalf("exit code %d, stderr: %s", exitCode, stderr.String())
	}
	var capabilities []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &capabilities); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(capabilities) != 1 || capabilities[0]["name"] != "system.status" {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}
}

func TestInvokeCommandUsesASeparateExitCodeForPolicyDenial(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	paths := startTestService(t)

	exitCode := run(
		[]string{"invoke", "secrets.reveal"},
		&stdout,
		&stderr,
		paths,
	)

	if exitCode != deniedExitCode {
		t.Fatalf("exit code %d, want %d; stderr: %s", exitCode, deniedExitCode, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if result["allowed"] != false || result["reason"] != "unknown capability" {
		t.Fatalf("unexpected denial: %#v", result)
	}
}

func TestRuntimeDefaultsUseSystemPathsOnLinux(t *testing.T) {
	paths := defaultPathsFor("linux", "/home/deploy", "", "")
	if paths.socket != "/run/keybroker/keybroker.sock" {
		t.Fatalf("Linux socket = %q", paths.socket)
	}
	if paths.audit != "/var/lib/keybroker/audit.jsonl" {
		t.Fatalf("Linux audit = %q", paths.audit)
	}
}

func TestRuntimeDefaultsPreserveExplicitOverrides(t *testing.T) {
	paths := defaultPathsFor("linux", "/home/deploy", "/tmp/audit.jsonl", "/tmp/keybroker.sock")
	if paths.socket != "/tmp/keybroker.sock" || paths.audit != "/tmp/audit.jsonl" {
		t.Fatalf("overrides were not preserved: %#v", paths)
	}
}

func startTestService(t *testing.T) runtimePaths {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "kb-cli-")
	if err != nil {
		t.Fatalf("create test service directory: %v", err)
	}
	paths := runtimePaths{
		audit:  filepath.Join(root, "audit.jsonl"),
		socket: filepath.Join(root, "keybroker.sock"),
	}
	audit, err := keybroker.NewJSONLAudit(paths.audit)
	if err != nil {
		t.Fatalf("create test audit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- keybroker.ServeUnix(ctx, paths.socket, keybroker.NewDefault(audit))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(paths.socket); err == nil {
			t.Cleanup(func() {
				cancel()
				<-serverErrors
				_ = os.RemoveAll(root)
			})
			return paths
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatalf("test service did not create socket: %s", paths.socket)
	return runtimePaths{}
}
