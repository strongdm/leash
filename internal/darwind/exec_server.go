//go:build darwin

package darwind

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	execServerPort          = "18080"
	execHealthURL           = "http://127.0.0.1:18080/healthz"
	execStateFilename       = "darwin-exec-server-state.json"
	execLockFilename        = "darwin-exec-server-state.lock"
	execLogFilename         = "leash.log"
	execServerReadyTimeout  = 10 * time.Second
	execServerShutdownGrace = 5 * time.Second
	execDefaultPolicyPath   = "/tmp/tmp.leash.policy"
)

var execHTTPClient = &http.Client{Timeout: 250 * time.Millisecond}

type execServerHandle struct {
	managed   bool
	statePath string
	lockPath  string
	serverPID int
	clientPID int
}

func (h *execServerHandle) Release() error {
	if h == nil || !h.managed {
		return nil
	}

	lockFile, err := lockExecState(h.lockPath)
	if err != nil {
		return err
	}
	defer unlockExecState(lockFile)

	state, err := readExecServerState(h.statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("failed to read darwin exec state during release: %v", err)
		}
		state = execServerState{}
	}

	state.pruneClients()
	state.removeClient(h.clientPID)

	return writeExecServerState(h.statePath, state)
}

func acquireExecServer() (*execServerHandle, error) {
	stateDir, err := execStateDir()
	if err != nil {
		return nil, err
	}

	lockPath := filepath.Join(stateDir, execLockFilename)
	statePath := filepath.Join(stateDir, execStateFilename)
	desiredLogPath := filepath.Join(stateDir, execLogFilename)

	lockFile, err := lockExecState(lockPath)
	if err != nil {
		return nil, err
	}
	defer unlockExecState(lockFile)

	state, err := readExecServerState(statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("failed to parse darwin exec state: %v", err)
		}
		state = execServerState{}
	}

	state.pruneClients()

	if state.Managed {
		if strings.TrimSpace(state.LogPath) == "" || !sameFile(state.LogPath, desiredLogPath) {
			if state.ServerPID > 0 && processExists(state.ServerPID) {
				if err := terminateProcess(state.ServerPID); err != nil && !errors.Is(err, syscall.ESRCH) {
					log.Printf("failed to restart darwin exec server (pid %d): %v", state.ServerPID, err)
				}
			}
			state = execServerState{}
		}
		if state.ServerPID <= 0 || !processExists(state.ServerPID) {
			state = execServerState{}
		} else if err := waitForServerReady(state.ServerPID, execServerReadyTimeout); err != nil {
			log.Printf("darwin exec server (pid %d) not ready: %v", state.ServerPID, err)
			if stopErr := terminateProcess(state.ServerPID); stopErr != nil && !errors.Is(stopErr, syscall.ESRCH) {
				log.Printf("failed to terminate unready darwin exec server (pid %d): %v", state.ServerPID, stopErr)
			}
			state = execServerState{}
		}
	}

	if !state.Managed {
		if checkServerHealthy() {
			// External server already running; do not manage lifecycle.
			if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			return &execServerHandle{
				managed:   false,
				statePath: statePath,
				lockPath:  lockPath,
				clientPID: os.Getpid(),
			}, nil
		}

		available, err := portAvailable(":" + execServerPort)
		if err != nil {
			return nil, err
		}
		if !available {
			return nil, fmt.Errorf("leash Control UI requires port %s, but it is already in use", execServerPort)
		}

		pid, err := startManagedServer(stateDir, desiredLogPath)
		if err != nil {
			return nil, err
		}
		if err := waitForServerReady(pid, execServerReadyTimeout); err != nil {
			_ = terminateProcess(pid)
			return nil, err
		}
		state = execServerState{
			Managed:   true,
			ServerPID: pid,
			LogPath:   desiredLogPath,
		}
	}

	state.addClient(os.Getpid())
	state.Version = 1
	if err := writeExecServerState(statePath, state); err != nil {
		if len(state.Clients) == 1 {
			_ = terminateProcess(state.ServerPID)
			_ = os.Remove(statePath)
		}
		return nil, err
	}

	return &execServerHandle{
		managed:   state.Managed,
		statePath: statePath,
		lockPath:  lockPath,
		serverPID: state.ServerPID,
		clientPID: os.Getpid(),
	}, nil
}

func stopManagedExecServer() error {
	stateDir, err := execStateDir()
	if err != nil {
		return err
	}

	lockPath := filepath.Join(stateDir, execLockFilename)
	statePath := filepath.Join(stateDir, execStateFilename)

	lockFile, err := lockExecState(lockPath)
	if err != nil {
		return err
	}
	defer unlockExecState(lockFile)

	state, err := readExecServerState(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if checkServerHealthy() {
				return fmt.Errorf("no managed Leash macOS runtime found, but port %s is in use", execServerPort)
			}
			fmt.Println("No managed Leash macOS runtime is currently running.")
			return nil
		}
		return err
	}

	if !state.Managed || state.ServerPID <= 0 {
		if checkServerHealthy() {
			return fmt.Errorf("no managed Leash macOS runtime found, but port %s is in use", execServerPort)
		}
		if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("No managed Leash macOS runtime is currently running.")
		return nil
	}

	if err := terminateProcess(state.ServerPID); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("stop darwin exec server (pid %d): %w", state.ServerPID, err)
	}

	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	fmt.Println("Stopped Leash macOS runtime server on 127.0.0.1:18080.")
	return nil
}

type execServerState struct {
	Managed   bool   `json:"managed"`
	ServerPID int    `json:"server_pid"`
	Clients   []int  `json:"clients"`
	LogPath   string `json:"log_path,omitempty"`
	Version   int    `json:"version,omitempty"`
}

func (s *execServerState) pruneClients() {
	if len(s.Clients) == 0 {
		return
	}
	var alive []int
	for _, pid := range s.Clients {
		if processExists(pid) {
			alive = append(alive, pid)
		}
	}
	s.Clients = alive
}

func (s *execServerState) addClient(pid int) {
	if pid <= 0 {
		return
	}
	for _, existing := range s.Clients {
		if existing == pid {
			return
		}
	}
	s.Clients = append(s.Clients, pid)
	sort.Ints(s.Clients)
}

func (s *execServerState) removeClient(pid int) {
	for i, existing := range s.Clients {
		if existing == pid {
			s.Clients = append(s.Clients[:i], s.Clients[i+1:]...)
			return
		}
	}
}

func execStateDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("LEASH_DARWIN_STATE_DIR")); override != "" {
		if err := os.MkdirAll(override, 0o700); err != nil {
			return "", err
		}
		return override, nil
	}

	base, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(base) == "" {
		base = filepath.Join(os.TempDir(), "leash")
	} else {
		base = filepath.Join(base, "leash")
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return base, nil
}

func lockExecState(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func unlockExecState(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func readExecServerState(path string) (execServerState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return execServerState{}, nil
		}
		return execServerState{}, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return execServerState{}, nil
	}

	var state execServerState
	if err := json.Unmarshal(data, &state); err != nil {
		return execServerState{}, err
	}
	return state, nil
}

func writeExecServerState(path string, state execServerState) error {
	buf, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func checkServerHealthy() bool {
	if !probeHealthz() {
		return false
	}
	return probeWebInterface()
}

func probeHealthz() bool {
	resp, err := execHTTPClient.Get(execHealthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func probeWebInterface() bool {
	resp, err := execHTTPClient.Get("http://127.0.0.1:18080/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false
	}
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

func waitForServerReady(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if !processExists(pid) {
			return fmt.Errorf("process %d exited before Control UI became ready", pid)
		}
		if checkServerHealthy() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for leash Control UI on %s", execHealthURL)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func portAvailable(addr string) (bool, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if isAddrInUse(err) {
			return false, nil
		}
		return false, err
	}
	_ = ln.Close()
	return true, nil
}

func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			return errors.Is(sysErr.Err, syscall.EADDRINUSE)
		}
		return errors.Is(opErr.Err, syscall.EADDRINUSE)
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return errors.Is(sysErr.Err, syscall.EADDRINUSE)
	}
	return errors.Is(err, syscall.EADDRINUSE)
}

func startManagedServer(stateDir, logPath string) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve leash executable: %w", err)
	}
	cmd := exec.Command(executable, "--darwin")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	policyPath := execDefaultPolicyPath
	env := os.Environ()
	env = append(env, "LEASH_POLICY="+policyPath)
	env = append(env, "LEASH_LOG="+logPath)
	cmd.Env = env

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open log file %q: %w", logPath, err)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start leash --darwin runtime: %w", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		log.Printf("failed to release leash --darwin runtime process handle: %v", err)
	}
	return pid, nil
}

func terminateProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	if !processExists(pid) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(execServerShutdownGrace)
	for processExists(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if processExists(pid) {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func sameFile(a, b string) bool {
	cleanA := filepath.Clean(strings.TrimSpace(a))
	cleanB := filepath.Clean(strings.TrimSpace(b))
	if cleanA == "" || cleanB == "" {
		return false
	}
	if cleanA == cleanB {
		return true
	}
	infoA, errA := os.Stat(cleanA)
	if errA != nil {
		return false
	}
	infoB, errB := os.Stat(cleanB)
	if errB != nil {
		return false
	}
	return os.SameFile(infoA, infoB)
}
