package encoding

import (
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/policy/suggest/pattern"
)

func TestBagOfNGramsNormalizesCounts(t *testing.T) {
	seq := pattern.Sequence{
		SessionID: "s1",
		Principal: "user",
		Events: []pattern.Event{
			makeEvent("filesystem", "open", "unix.file"),
			makeEvent("filesystem", "read", "unix.file"),
			makeEvent("network", "connect", "net.host"),
		},
	}
	vec := BagOfNGramsN(2)(seq)
	sum := 0.0
	for _, v := range vec {
		sum += v
	}
	if sum < 0.99 || sum > 1.01 {
		t.Fatalf("expected normalized histogram, got %f", sum)
	}
}

func TestAffinityClusterBuildsGroups(t *testing.T) {
	base := time.Now()
	trace := func(id string, actions ...string) pattern.Sequence {
		evts := make([]pattern.Event, len(actions))
		for i, act := range actions {
			parts := strings.Split(act, ":")
			evts[i] = pattern.Event{
				Timestamp:     base.Add(time.Duration(i) * time.Second),
				PrincipalID:   id,
				ActionFamily:  parts[0],
				ActionName:    parts[1],
				ResourceClass: parts[2],
				ResourceFacet: parts[3],
				Outcome:       "permit",
			}
		}
		return pattern.Sequence{SessionID: id, Principal: id, Events: evts}
	}

	traces := []pattern.Sequence{
		trace("s1", "filesystem:open:unix.file:/etc", "filesystem:read:unix.file:/etc", "network:connect:net.host:api"),
		trace("s2", "filesystem:open:unix.file:/etc", "filesystem:read:unix.file:/etc", "network:connect:net.host:api"),
		trace("s3", "process:exec:process.binary:/usr/bin/python", "network:connect:net.host:s3"),
		trace("s4", "process:exec:process.binary:/usr/bin/python", "network:connect:net.host:s3"),
	}

	clusters := AffinityCluster(traces, BagOfNGramsN(2), 0.7)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}
	for _, cl := range clusters {
		if len(cl.Members) != 2 {
			t.Fatalf("expected cluster size 2, got %d", len(cl.Members))
		}
	}
}

func makeEvent(family, action, resource string) pattern.Event {
	return pattern.Event{
		ActionFamily:  family,
		ActionName:    action,
		ResourceClass: resource,
		Outcome:       "permit",
	}
}
