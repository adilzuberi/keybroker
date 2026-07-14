package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adilzuberi/keybroker"
)

func TestMCPListsAndCallsOnlyBrokeredStatusTool(t *testing.T) {
	socket := startMCPTestService(t)
	input := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keybroker_system_status","arguments":{}}}` + "\n",
	)
	var output bytes.Buffer

	if err := runMCP(input, &output, socket); err != nil {
		t.Fatalf("run MCP adapter: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d replies, want 3: %s", len(lines), output.String())
	}
	var listed struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listed); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(listed.Result.Tools) != 1 || listed.Result.Tools[0].Name != "keybroker_system_status" {
		t.Fatalf("unexpected tools: %#v", listed.Result.Tools)
	}
	if !strings.Contains(lines[2], `\"status\":\"ok\"`) {
		t.Fatalf("status tool did not return broker health: %s", lines[2])
	}
}

func TestDefaultSocketUsesSystemPathOnLinux(t *testing.T) {
	if got := defaultSocketPathFor("linux", "/home/deploy", ""); got != "/run/keybroker/keybroker.sock" {
		t.Fatalf("Linux socket = %q", got)
	}
}

func startMCPTestService(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "kb-mcp-")
	if err != nil {
		t.Fatalf("create MCP test directory: %v", err)
	}
	socket := filepath.Join(root, "keybroker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- keybroker.ServeUnix(ctx, socket, keybroker.NewDefault(keybroker.DiscardAudit()))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			t.Cleanup(func() {
				cancel()
				<-serverErrors
				_ = os.RemoveAll(root)
			})
			return socket
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatalf("MCP test service did not create socket")
	return ""
}
