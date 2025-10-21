package suggest

import "time"

// Options controls thresholds and knobs for generating mechanical suggestions.
type Options struct {
	// MinDirectoryGroup is the minimum number of file policies sharing the same
	// directory required before we emit a directory container suggestion.
	MinDirectoryGroup int

	// MinDomainGroup is the minimum number of network policies sharing the same
	// base domain before recommending a wildcard/Domain container.
	MinDomainGroup int

	// MinHTTPGroup is the minimum number of HTTP rewrite rules that share the
	// same host or base domain before suggesting a rewrite bundle.
	MinHTTPGroup int

	// MinSequenceSupport is the minimum number of sessions supporting a mined
	// workflow motif before surfacing a suggestion.
	MinSequenceSupport int

	// MaxSequenceLength bounds the number of events considered when mining
	// targeted sequences ending in a destination action.
	MaxSequenceLength int

	// ClusterSimilarity controls the cosine similarity threshold for grouping
	// traces via affinity clustering.
	ClusterSimilarity float64

	// SessionWindow controls how events are bucketed into logical sessions when
	// constructing trace sequences.
	SessionWindow time.Duration

	// DriftThreshold determines when PSI drift detection should flag a cluster.
	DriftThreshold float64

	// TailLimit bounds the number of ring buffer events ingested per analysis
	// run. A value <= 0 means inspect the entire buffer.
	TailLimit int

	// MaxClusters limits the number of workflow clusters returned per analysis.
	MaxClusters int

	// MinClusterSize filters clusters with too few member sessions.
	MinClusterSize int
}

// DefaultOptions returns a conservative set of thresholds suitable for initial
// UX experiments. These values can be tuned at runtime or overridden in unit
// tests.
func DefaultOptions() Options {
	return Options{
		MinDirectoryGroup:  3,
		MinDomainGroup:     3,
		MinHTTPGroup:       2,
		MinSequenceSupport: 3,
		MaxSequenceLength:  4,
		ClusterSimilarity:  0.72,
		SessionWindow:      10 * time.Minute,
		DriftThreshold:     0.25,
		TailLimit:          10000,
		MaxClusters:        8,
		MinClusterSize:     2,
	}
}
