package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/adilzuberi/keybroker"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func main() {
	if err := runMCP(os.Stdin, os.Stdout, defaultSocketPath()); err != nil {
		fmt.Fprintln(os.Stderr, "keybroker-mcp:", err)
		os.Exit(1)
	}
}

func runMCP(input io.Reader, output io.Writer, socketPath string) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var request mcpRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = encoder.Encode(errorResponse(nil, -32700, "Parse error"))
			continue
		}
		if len(request.ID) == 0 || string(request.ID) == "null" {
			continue
		}
		response := handleMCP(request, socketPath)
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("write MCP response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP request: %w", err)
	}
	return nil
}

func handleMCP(request mcpRequest, socketPath string) map[string]any {
	switch request.Method {
	case "initialize":
		return resultResponse(request.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "keybroker", "version": "0.1.0"},
		})
	case "ping":
		return resultResponse(request.ID, map[string]any{})
	case "tools/list":
		return resultResponse(request.ID, map[string]any{"tools": []map[string]any{{
			"name":        "keybroker_system_status",
			"description": "Check whether the local Keybroker gatekeeper is available.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}}})
	case "tools/call":
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(request.Params, &params); err != nil || params.Name != "keybroker_system_status" {
			return errorResponse(request.ID, -32602, "Unknown Keybroker tool")
		}
		result, err := keybroker.InvokeUnix(context.Background(), socketPath, keybroker.Request{Capability: "system.status"})
		if err != nil {
			return resultResponse(request.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": "Keybroker unavailable"}},
				"isError": true,
			})
		}
		text, _ := json.Marshal(result)
		return resultResponse(request.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(text)}},
		})
	default:
		return errorResponse(request.ID, -32601, "Method not found")
	}
}

func resultResponse(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func errorResponse(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	}
}

func defaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return defaultSocketPathFor(runtime.GOOS, home, os.Getenv("KEYBROKER_SOCKET"))
}

func defaultSocketPathFor(goos, home, configured string) string {
	if configured != "" {
		return configured
	}
	if goos == "linux" {
		return "/run/keybroker/keybroker.sock"
	}
	return filepath.Join(home, "Library", "Application Support", "Keybroker", "keybroker.sock")
}
