package keybroker_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adilzuberi/keybroker"
)

func TestJSONLAuditAppendsPrivateRedactedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	audit, err := keybroker.NewJSONLAudit(path)
	if err != nil {
		t.Fatalf("create audit sink: %v", err)
	}

	err = audit.Write(keybroker.AuditEvent{
		Time:       time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC),
		Caller:     "local-cli",
		Capability: "system.status",
		Allowed:    true,
		Reason:     "allowed by local policy",
		Input:      map[string]any{"api_token": "should-never-appear"},
	})
	if err != nil {
		t.Fatalf("write audit event: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if strings.Contains(string(data), "should-never-appear") {
		t.Fatalf("audit contains a secret value: %s", data)
	}
	if !strings.Contains(string(data), `"api_token":"[REDACTED]"`) {
		t.Fatalf("audit lacks redaction marker: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode is %o, want 600", info.Mode().Perm())
	}
}
