package suggest

import (
	"testing"
	"time"

	"github.com/strongdm/leash/internal/policy/suggest/pattern"
	"github.com/strongdm/leash/internal/websocket"
)

func TestBuildSequencesFromLogsGroupsByPrincipal(t *testing.T) {
	logs := []websocket.LogEntry{
		{Time: "2025-10-11T15:04:05Z", Event: "file.open", Path: "/etc/ssh/sshd_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:04:08Z", Event: "file.open", Path: "/etc/ssh/ssh_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:06:05Z", Event: "http.request", Addr: "api.example.com", Tool: "curl", Decision: "permit"},
	}

	seqs := BuildSequencesFromLogs(logs, 5*time.Minute)
	if len(seqs) != 2 {
		t.Fatalf("expected 2 sequences, got %d", len(seqs))
	}

	var fileSeq, httpSeq pattern.Sequence
	for _, seq := range seqs {
		if seq.Principal == "vim" {
			fileSeq = seq
		}
		if seq.Principal == "curl" {
			httpSeq = seq
		}
	}

	if len(fileSeq.Events) != 2 {
		t.Fatalf("expected 2 file events, got %d", len(fileSeq.Events))
	}
	if fileSeq.Events[0].ResourceClass != "unix.file" {
		t.Fatalf("unexpected resource class %s", fileSeq.Events[0].ResourceClass)
	}
	if httpSeq.Events[0].ResourceClass != "http.host" {
		t.Fatalf("expected http host resource, got %s", httpSeq.Events[0].ResourceClass)
	}
}
