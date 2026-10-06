package keybroker

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Set only in managed MCP release builds. It cannot be set by a caller's env.
var ManagedMCP = "0"

func CheckManagedRelease() error {
	if ManagedMCP != "1" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/local/libexec/keybroker-health-maintain", "check")
	// Parse fixed safe metadata; root helper output cannot corrupt MCP framing.
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("approved release unavailable")
	}
	var info struct {
		Release string `json:"release"`
		Source  string `json:"source"`
	}
	if len(data) > 65536 || json.Unmarshal(data, &info) != nil || info.Release != ReleaseID || info.Source != SourceID {
		return fmt.Errorf("restart the MCP client to load the approved release")
	}
	return nil
}
