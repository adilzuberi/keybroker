package keybroker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maxUnixRequestBytes = 64 * 1024
const maxUnixSocketPathBytes = 103

type unixRequest struct {
	Operation string  `json:"operation"`
	Request   Request `json:"request"`
}

type unixResponse struct {
	Capabilities []Capability `json:"capabilities,omitempty"`
	Decision     *Decision    `json:"decision,omitempty"`
	Result       *Result      `json:"result,omitempty"`
	Error        string       `json:"error,omitempty"`
}

func ServeUnix(ctx context.Context, socketPath string, broker *Broker) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required")
	}
	if len([]byte(socketPath)) > maxUnixSocketPathBytes {
		return fmt.Errorf("socket path is too long: use at most %d bytes", maxUnixSocketPathBytes)
	}
	if broker == nil {
		return fmt.Errorf("broker is required")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := prepareSocketPath(socketPath); err != nil {
		return err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("protect unix socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept unix connection: %w", err)
		}
		go handleUnixConnection(ctx, connection, broker)
	}
}

func prepareSocketPath(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refuse to replace non-socket path")
	}

	connection, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if dialErr == nil {
		connection.Close()
		return fmt.Errorf("keybroker is already running")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
		return fmt.Errorf("probe existing socket: %w", dialErr)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func handleUnixConnection(ctx context.Context, connection net.Conn, broker *Broker) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(10 * time.Second))

	decoder := json.NewDecoder(io.LimitReader(connection, maxUnixRequestBytes))
	var request unixRequest
	if err := decoder.Decode(&request); err != nil {
		writeUnixResponse(connection, unixResponse{Error: "invalid request"})
		return
	}
	switch request.Operation {
	case "capabilities":
		writeUnixResponse(connection, unixResponse{Capabilities: broker.Capabilities()})
		return
	case "check":
		request.Request.Caller = "local-user"
		decision := broker.Check(request.Request)
		writeUnixResponse(connection, unixResponse{Decision: &decision})
		return
	case "invoke":
		request.Request.Caller = "local-user"
		result, err := broker.Invoke(ctx, request.Request)
		if err != nil {
			writeUnixResponse(connection, unixResponse{Error: "broker unavailable"})
			return
		}
		writeUnixResponse(connection, unixResponse{Result: &result})
		return
	default:
		writeUnixResponse(connection, unixResponse{Error: "unknown operation"})
		return
	}
}

func writeUnixResponse(output io.Writer, response unixResponse) {
	_ = json.NewEncoder(output).Encode(response)
}

func InvokeUnix(ctx context.Context, socketPath string, request Request) (Result, error) {
	response, err := callUnix(ctx, socketPath, unixRequest{Operation: "invoke", Request: request})
	if err != nil {
		return Result{}, err
	}
	if response.Result == nil {
		return Result{}, fmt.Errorf("keybroker returned no result")
	}
	return *response.Result, nil
}

func CheckUnix(ctx context.Context, socketPath string, request Request) (Decision, error) {
	response, err := callUnix(ctx, socketPath, unixRequest{Operation: "check", Request: request})
	if err != nil {
		return Decision{}, err
	}
	if response.Decision == nil {
		return Decision{}, fmt.Errorf("keybroker returned no decision")
	}
	return *response.Decision, nil
}

func CapabilitiesUnix(ctx context.Context, socketPath string) ([]Capability, error) {
	response, err := callUnix(ctx, socketPath, unixRequest{Operation: "capabilities"})
	if err != nil {
		return nil, err
	}
	return response.Capabilities, nil
}

func callUnix(ctx context.Context, socketPath string, message unixRequest) (unixResponse, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return unixResponse{}, fmt.Errorf("connect to keybroker: %w", err)
	}
	defer connection.Close()

	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	} else {
		connection.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := json.NewEncoder(connection).Encode(message); err != nil {
		return unixResponse{}, fmt.Errorf("send keybroker request: %w", err)
	}

	reader := bufio.NewReader(io.LimitReader(connection, maxUnixRequestBytes))
	var response unixResponse
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return unixResponse{}, fmt.Errorf("read keybroker response: %w", err)
	}
	if response.Error != "" {
		return unixResponse{}, fmt.Errorf("keybroker: %s", response.Error)
	}
	return response, nil
}
