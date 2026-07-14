package keybroker

import (
	"context"
	"sort"
	"strings"
	"time"
)

type Risk string

const RiskReadOnly Risk = "read-only"

type Capability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        Risk   `json:"risk"`
}

type Request struct {
	Caller     string         `json:"caller"`
	Capability string         `json:"capability"`
	Input      map[string]any `json:"input,omitempty"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Result struct {
	Allowed    bool           `json:"allowed"`
	Capability string         `json:"capability"`
	Reason     string         `json:"reason"`
	Output     map[string]any `json:"output,omitempty"`
}

type AuditSink interface {
	Write(AuditEvent) error
}

type AuditEvent struct {
	Time       time.Time      `json:"time"`
	Caller     string         `json:"caller"`
	Capability string         `json:"capability"`
	Allowed    bool           `json:"allowed"`
	Reason     string         `json:"reason"`
	Input      map[string]any `json:"input,omitempty"`
}

type discardAudit struct{}

func (discardAudit) Write(AuditEvent) error { return nil }

func DiscardAudit() AuditSink { return discardAudit{} }

type Broker struct {
	capabilities map[string]Capability
	audit        AuditSink
}

func NewDefault(audit AuditSink) *Broker {
	if audit == nil {
		audit = DiscardAudit()
	}

	status := Capability{
		Name:        "system.status",
		Description: "Report whether the local Keybroker core is available.",
		Risk:        RiskReadOnly,
	}

	return &Broker{
		capabilities: map[string]Capability{status.Name: status},
		audit:        audit,
	}
}

func (b *Broker) Capabilities() []Capability {
	capabilities := make([]Capability, 0, len(b.capabilities))
	for _, capability := range b.capabilities {
		capabilities = append(capabilities, capability)
	}
	sort.Slice(capabilities, func(i, j int) bool {
		return capabilities[i].Name < capabilities[j].Name
	})
	return capabilities
}

func (b *Broker) Check(request Request) Decision {
	if request.Caller == "" {
		return Decision{Reason: "caller is required"}
	}
	if _, exists := b.capabilities[request.Capability]; !exists {
		return Decision{Reason: "unknown capability"}
	}
	if request.Caller != "local-cli" && request.Caller != "local-user" {
		return Decision{Reason: "caller is not allowed"}
	}
	return Decision{Allowed: true, Reason: "allowed by local policy"}
}

func (b *Broker) Invoke(_ context.Context, request Request) (Result, error) {
	decision := b.Check(request)
	result := Result{
		Allowed:    decision.Allowed,
		Capability: request.Capability,
		Reason:     decision.Reason,
	}
	if err := b.audit.Write(AuditEvent{
		Time:       time.Now().UTC(),
		Caller:     request.Caller,
		Capability: request.Capability,
		Allowed:    decision.Allowed,
		Reason:     decision.Reason,
		Input:      redactMap(request.Input),
	}); err != nil {
		result.Allowed = false
		result.Reason = "audit unavailable"
		return result, err
	}
	if !decision.Allowed {
		return result, nil
	}

	result.Output = map[string]any{
		"broker": "keybroker",
		"status": "ok",
	}
	return result, nil
}

func redactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	redacted := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey(key) {
			redacted[key] = "[REDACTED]"
			continue
		}
		redacted[key] = redactValue(value)
	}
	return redacted
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed)
	case []any:
		redacted := make([]any, len(typed))
		for index, item := range typed {
			redacted[index] = redactValue(item)
		}
		return redacted
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalised := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, marker := range []string{"password", "secret", "token", "authorization", "credential", "privatekey", "apikey"} {
		if strings.Contains(normalised, marker) {
			return true
		}
	}
	return false
}
