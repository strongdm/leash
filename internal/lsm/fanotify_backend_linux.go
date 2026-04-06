//go:build linux

package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const fanotifyTargetRoot = "/proc/1/root"

type fanotifyBackend struct {
	cgroupPath string
	logger     *SharedLogger

	mu               sync.RWMutex
	openRules        []OpenPolicyRule
	execRules        []ExecPolicyRule
	openDefaultAllow bool
	execDefaultAllow bool
}

func newFanotifyBackend(cgroupPath string, logger *SharedLogger) (*fanotifyBackend, error) {
	if strings.TrimSpace(cgroupPath) == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}
	return &fanotifyBackend{
		cgroupPath: cgroupPath,
		logger:     logger,
	}, nil
}

func (b *fanotifyBackend) UpdatePolicies(policies *PolicySet) error {
	if policies == nil {
		policies = &PolicySet{}
	}

	openRules := ConvertToFileOpenRules(policies.Open)
	sort.Slice(openRules, func(i, j int) bool {
		return openRules[i].PathLen > openRules[j].PathLen
	})

	execRules := ConvertToExecRules(policies.Exec)
	sort.Slice(execRules, func(i, j int) bool {
		return execRules[i].PathLen > execRules[j].PathLen
	})

	b.mu.Lock()
	defer b.mu.Unlock()
	b.openRules = openRules
	b.execRules = execRules
	b.openDefaultAllow = hasAllowedRootOpen(openRules)
	b.execDefaultAllow = hasAllowedRootExec(execRules)
	return nil
}

func (b *fanotifyBackend) Run() error {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT,
		unix.O_RDONLY|unix.O_LARGEFILE,
	)
	if err != nil {
		return fmt.Errorf("fanotify init: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
		unix.FAN_OPEN_PERM|unix.FAN_OPEN_EXEC_PERM,
		unix.AT_FDCWD,
		fanotifyTargetRoot,
	); err != nil {
		return fmt.Errorf("fanotify mark %s: %w", fanotifyTargetRoot, err)
	}

	now := time.Now().Format("15:04:05")
	fmt.Printf("time=%s level=info msg=\"Successfully started monitoring file opens and exec via fanotify\"\n", now)

	sigChan := make(chan os.Signal, 1)
	signalNotify(sigChan)
	defer signalStop(sigChan)

	buf := make([]byte, os.Getpagesize()*4)
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		select {
		case <-sigChan:
			end := time.Now().Format("15:04:05")
			fmt.Printf("time=%s level=info msg=\"Shutting down fanotify tracker\"\n", end)
			return nil
		default:
		}

		n, err := unix.Poll(pollFDs, 100)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("fanotify poll: %w", err)
		}
		if n == 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}

		readN, err := unix.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("fanotify read: %w", err)
		}
		if readN == 0 {
			continue
		}

		if err := b.handleBuffer(fd, buf[:readN]); err != nil {
			return err
		}
	}
}

func (b *fanotifyBackend) handleBuffer(fanotifyFD int, buf []byte) error {
	offset := 0
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for offset+metaSize <= len(buf) {
		var meta unix.FanotifyEventMetadata
		if err := binary.Read(bytes.NewReader(buf[offset:offset+metaSize]), binary.LittleEndian, &meta); err != nil {
			return fmt.Errorf("parse fanotify event metadata: %w", err)
		}
		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			return fmt.Errorf("fanotify metadata version mismatch: got %d want %d", meta.Vers, unix.FANOTIFY_METADATA_VERSION)
		}
		if meta.Event_len < uint32(metaSize) {
			return fmt.Errorf("invalid fanotify event length %d", meta.Event_len)
		}

		if meta.Fd >= 0 {
			b.handleEvent(fanotifyFD, meta)
		}
		offset += int(meta.Event_len)
	}
	return nil
}

func (b *fanotifyBackend) handleEvent(fanotifyFD int, meta unix.FanotifyEventMetadata) {
	defer unix.Close(int(meta.Fd))

	path := readFDPath(int(meta.Fd))
	comm := readProcComm(int(meta.Pid))
	cgroupID := readProcCgroupID(int(meta.Pid))
	timestamp := time.Now().Format(time.RFC3339)

	allowed := true
	var logEntry string

	switch {
	case meta.Mask&unix.FAN_OPEN_EXEC_PERM != 0:
		args := readProcArgs(int(meta.Pid))
		allowed = b.allowExec(path, args)
		decision := "allowed"
		if !allowed {
			decision = "denied"
		}
		if len(args) > 0 {
			logEntry = fmt.Sprintf(
				"time=%s event=proc.exec pid=%d cgroup=%d exe=\"%s\" path=\"%s\" argc=%d argv=\"%s\" decision=%s",
				timestamp, meta.Pid, cgroupID, comm, path, len(args), strings.Join(args, " "), decision,
			)
		} else {
			logEntry = fmt.Sprintf(
				"time=%s event=proc.exec pid=%d cgroup=%d exe=\"%s\" path=\"%s\" argc=%d decision=%s",
				timestamp, meta.Pid, cgroupID, comm, path, len(args), decision,
			)
		}
	case meta.Mask&unix.FAN_OPEN_PERM != 0:
		allowed = b.allowOpen(path)
		decision := "allowed"
		if !allowed {
			decision = "denied"
		}
		// fanotify open permission events do not expose the original open flags, so the
		// fallback reports the generic file.open event name.
		logEntry = fmt.Sprintf(
			"time=%s event=file.open pid=%d cgroup=%d exe=\"%s\" path=\"%s\" decision=%s",
			timestamp, meta.Pid, cgroupID, comm, path, decision,
		)
	default:
		return
	}

	if b.logger != nil {
		_ = b.logger.Write(logEntry)
	}

	response := unix.FAN_ALLOW
	if !allowed {
		response = unix.FAN_DENY
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, unix.FanotifyResponse{
		Fd:       meta.Fd,
		Response: uint32(response),
	})
	_, _ = unix.Write(fanotifyFD, out.Bytes())
}

func (b *fanotifyBackend) allowOpen(path string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, rule := range b.openRules {
		rulePath := bytesToRulePath(rule.Path[:], int(rule.PathLen))
		if !strings.HasPrefix(path, rulePath) {
			continue
		}
		return rule.Action == PolicyAllow
	}
	return b.openDefaultAllow
}

func (b *fanotifyBackend) allowExec(path string, args []string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, rule := range b.execRules {
		rulePath := bytesToRulePath(rule.Path[:], int(rule.PathLen))
		if !strings.HasPrefix(path, rulePath) {
			continue
		}
		if rule.ArgCount == 0 {
			return rule.Action == PolicyAllow
		}
		if rule.Action == PolicyDeny && execArgsMatch(rule, args) {
			return false
		}
	}
	return b.execDefaultAllow
}

func execArgsMatch(rule ExecPolicyRule, args []string) bool {
	if len(args) <= 1 {
		return false
	}
	for i := int32(0); i < rule.ArgCount && i < 4; i++ {
		needle := string(bytes.TrimRight(rule.Args[i][:rule.ArgLens[i]], "\x00"))
		if needle == "" {
			continue
		}
		for _, arg := range args[1:] {
			if arg == needle {
				return true
			}
		}
	}
	return false
}

func hasAllowedRootOpen(rules []OpenPolicyRule) bool {
	for _, rule := range rules {
		if rule.Action == PolicyAllow && bytesToRulePath(rule.Path[:], int(rule.PathLen)) == "/" {
			return true
		}
	}
	return false
}

func hasAllowedRootExec(rules []ExecPolicyRule) bool {
	for _, rule := range rules {
		if rule.Action == PolicyAllow && bytesToRulePath(rule.Path[:], int(rule.PathLen)) == "/" {
			return true
		}
	}
	return false
}

func bytesToRulePath(raw []byte, n int) string {
	if n <= 0 || n > len(raw) {
		return ""
	}
	return string(bytes.TrimRight(raw[:n], "\x00"))
}

func readFDPath(fd int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil && resolved != "" {
		return resolved
	}
	return path
}

func readProcComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcArgs(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	parts := strings.Split(string(bytes.TrimRight(data, "\x00")), "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readProcCgroupID(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		raw := parts[len(parts)-1]
		raw = strings.TrimSpace(raw)
		if raw == "" || raw == "/" || raw == "." {
			continue
		}
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		path := filepath.Clean(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(raw, "/")))
		id, err := getCgroupID(path)
		if err == nil {
			return id
		}
	}
	return 0
}

func signalNotify(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func signalStop(ch chan<- os.Signal) {
	signal.Stop(ch)
}
