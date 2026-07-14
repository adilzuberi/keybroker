package keybroker_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adilzuberi/keybroker"
)

func TestUnixServiceOwnsCallerIdentityAndProtectsItsSocket(t *testing.T) {
	audit := &captureAudit{}
	broker := keybroker.NewDefault(audit)
	shortRoot, err := os.MkdirTemp("/tmp", "kb-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortRoot) })
	socketPath := filepath.Join(shortRoot, "keybroker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- keybroker.ServeUnix(ctx, socketPath, broker)
	}()
	waitForSocket(t, socketPath, serverErrors)

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode is %o, want 600", info.Mode().Perm())
	}

	result, err := keybroker.InvokeUnix(context.Background(), socketPath, keybroker.Request{
		Caller:     "spoofed-cloud-model",
		Capability: "system.status",
	})
	if err != nil {
		t.Fatalf("invoke over unix socket: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("status denied: %s", result.Reason)
	}
	if len(audit.events) != 1 || audit.events[0].Caller != "local-user" {
		t.Fatalf("service trusted caller input: %#v", audit.events)
	}

	cancel()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("stop unix service: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unix service did not stop")
	}
}

func TestUnixServiceRecoversOnlyAStaleSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "kb-stale-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socketPath := filepath.Join(root, "keybroker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- keybroker.ServeUnix(ctx, socketPath, keybroker.NewDefault(keybroker.DiscardAudit()))
	}()
	result := waitForStatus(t, socketPath, serverErrors)
	if !result.Allowed {
		t.Fatalf("recovered service denied status: %s", result.Reason)
	}
	cancel()
	if err := <-serverErrors; err != nil {
		t.Fatalf("stop recovered service: %v", err)
	}
}

func waitForStatus(t *testing.T, socketPath string, serverErrors <-chan error) keybroker.Result {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serverErrors:
			t.Fatalf("unix service stopped before recovery: %v", err)
		default:
		}
		result, err := keybroker.InvokeUnix(context.Background(), socketPath, keybroker.Request{Capability: "system.status"})
		if err == nil {
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("unix service did not recover stale socket")
	return keybroker.Result{}
}

func waitForSocket(t *testing.T, path string, serverErrors <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serverErrors:
			t.Fatalf("unix service stopped before creating its socket: %v", err)
		default:
		}
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket did not appear: %s", path)
}
