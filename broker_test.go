package keybroker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/adilzuberi/keybroker"
)

type captureAudit struct {
	events []keybroker.AuditEvent
}

type failingAudit struct{}

func (failingAudit) Write(keybroker.AuditEvent) error {
	return errors.New("disk unavailable")
}

func (a *captureAudit) Write(event keybroker.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func TestDefaultBrokerListsOnlyTheSafeStatusCapability(t *testing.T) {
	broker := keybroker.NewDefault(keybroker.DiscardAudit())

	capabilities := broker.Capabilities()

	if len(capabilities) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(capabilities))
	}
	if capabilities[0].Name != "system.status" {
		t.Fatalf("got capability %q, want system.status", capabilities[0].Name)
	}
	if capabilities[0].Risk != keybroker.RiskReadOnly {
		t.Fatalf("got risk %q, want %q", capabilities[0].Risk, keybroker.RiskReadOnly)
	}
}

func TestAllowedStatusInvocationReturnsOnlyBrokerHealth(t *testing.T) {
	broker := keybroker.NewDefault(keybroker.DiscardAudit())

	result, err := broker.Invoke(context.Background(), keybroker.Request{
		Caller:     "local-cli",
		Capability: "system.status",
	})

	if err != nil {
		t.Fatalf("invoke status: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("status invocation denied: %s", result.Reason)
	}
	if result.Output["status"] != "ok" {
		t.Fatalf("got status %#v, want ok", result.Output["status"])
	}
	if len(result.Output) != 2 || result.Output["broker"] != "keybroker" {
		t.Fatalf("unexpected status output: %#v", result.Output)
	}
}

func TestUnknownCapabilityFailsClosed(t *testing.T) {
	broker := keybroker.NewDefault(keybroker.DiscardAudit())

	decision := broker.Check(keybroker.Request{
		Caller:     "local-cli",
		Capability: "secrets.reveal",
	})

	if decision.Allowed {
		t.Fatal("unknown capability was allowed")
	}
	if decision.Reason != "unknown capability" {
		t.Fatalf("got reason %q, want unknown capability", decision.Reason)
	}
}

func TestDeniedInvocationIsAuditedWithoutSecretValues(t *testing.T) {
	audit := &captureAudit{}
	broker := keybroker.NewDefault(audit)

	result, err := broker.Invoke(context.Background(), keybroker.Request{
		Caller:     "local-cli",
		Capability: "secrets.reveal",
		Input: map[string]any{
			"password": "should-never-appear",
			"account":  "example",
		},
	})

	if err != nil {
		t.Fatalf("invoke denied capability: %v", err)
	}
	if result.Allowed {
		t.Fatal("denied capability was allowed")
	}
	if len(audit.events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Input["password"] != "[REDACTED]" {
		t.Fatalf("password was not redacted: %#v", event.Input)
	}
	if event.Input["account"] != "example" {
		t.Fatalf("safe input was changed: %#v", event.Input)
	}
}

func TestInvocationFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	broker := keybroker.NewDefault(failingAudit{})

	result, err := broker.Invoke(context.Background(), keybroker.Request{
		Caller:     "local-cli",
		Capability: "system.status",
	})

	if err == nil {
		t.Fatal("audit failure was hidden")
	}
	if result.Allowed {
		t.Fatal("invocation ran without an audit record")
	}
	if result.Reason != "audit unavailable" {
		t.Fatalf("got reason %q, want audit unavailable", result.Reason)
	}
}
