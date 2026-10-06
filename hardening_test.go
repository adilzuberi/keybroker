package keybroker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRejectsLinksModesAndNonRegularFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "directory", "unsafe-parent"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			path := filepath.Join(d, "audit.jsonl")
			target := filepath.Join(d, "target")
			if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "unsafe-parent":
				if err := os.Chmod(d, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewJSONLAudit(path); err == nil {
				t.Fatal("unsafe audit accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "preserve" {
				t.Fatal("unrelated audit target changed")
			}
		})
	}
}

func TestAuditRechecksDescriptorAfterReplacement(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, "audit.jsonl")
	a, err := NewJSONLAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".retained", path); err != nil {
		t.Fatal(err)
	}
	if err := a.Write(AuditEvent{Caller: "local-user"}); err == nil {
		t.Fatal("replacement audit accepted")
	}
}

func TestSocketParentAndFakeFileDenied(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "keybroker.sock")
	if err := os.Chmod(d, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ServeUnix(context.Background(), p, NewDefault(DiscardAudit())); err == nil {
		t.Fatal("unsafe parent accepted")
	}
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CapabilitiesUnix(context.Background(), p); err == nil {
		t.Fatal("fake socket accepted")
	}
}

func TestKernelPeerIdentity(t *testing.T) {
	d, err := os.MkdirTemp("/tmp", "kb-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(d, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, c := range []*net.UnixConn{client, server} {
		uid, err := peerUID(c)
		if err != nil || int(uid) != os.Geteuid() {
			t.Fatalf("kernel peer: uid=%d err=%v", uid, err)
		}
		if !trustedPeer(c) {
			t.Fatal("same-account peer rejected")
		}
	}
	client.Close()
	if trustedPeer(client) {
		t.Fatal("closed peer accepted")
	}
}
