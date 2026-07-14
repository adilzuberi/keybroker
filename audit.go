package keybroker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type JSONLAudit struct {
	path string
	mu   sync.Mutex
}

func NewJSONLAudit(path string) (*JSONLAudit, error) {
	if path == "" {
		return nil, fmt.Errorf("audit path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("protect audit file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close audit file: %w", err)
	}
	return &JSONLAudit{path: path}, nil
}

func (a *JSONLAudit) Write(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	event.Input = redactMap(event.Input)
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	line = append(line, '\n')

	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer file.Close()

	written, err := file.Write(line)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if written != len(line) {
		return fmt.Errorf("append audit event: short write")
	}
	return nil
}
