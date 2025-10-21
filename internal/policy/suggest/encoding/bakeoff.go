package encoding

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/strongdm/leash/internal/policy/suggest/pattern"
)

// FeatureVector is a sparse representation for encoded traces.
type FeatureVector map[string]float64

// Cluster summarises a group of traces produced by the bake-off.
type Cluster struct {
	ID             string
	Members        []string
	Centroid       FeatureVector
	Explanation    string
	Representative pattern.Sequence
}

// BagOfNGrams encodes sequences as a normalized histogram of action/resource
// n-grams. Suitable for capturing unordered co-occurrence statistics. Default n=2.
func BagOfNGrams(seq pattern.Sequence) FeatureVector {
	return BagOfNGramsN(2)(seq)
}

// BagOfNGramsN provides a curried encoder that uses the supplied n.
func BagOfNGramsN(n int) func(pattern.Sequence) FeatureVector {
	return func(seq pattern.Sequence) FeatureVector {
		if n <= 0 {
			n = 2
		}
		events := seq.Events
		if len(events) == 0 {
			return FeatureVector{}
		}
		tokens := make([]string, len(events))
		for i, evt := range events {
			tokens[i] = strings.ToLower(evt.ActionFamily + ":" + evt.ActionName + ":" + evt.ResourceClass)
		}

		vec := make(FeatureVector)
		total := 0.0
		for i := 0; i <= len(tokens)-n; i++ {
			ng := strings.Join(tokens[i:i+n], "→")
			vec[ng]++
			total++
		}
		if total == 0 {
			total = 1
		}
		for k := range vec {
			vec[k] /= total
		}
		return vec
	}
}

// ConstraintTensorEncoding captures temporal ordering constraints by
// registering pairwise precedences with mean gap.
func ConstraintTensorEncoding(seq pattern.Sequence) FeatureVector {
	events := seq.Events
	vec := make(FeatureVector)
	if len(events) == 0 {
		return vec
	}
	for i := 0; i < len(events); i++ {
		lhs := canonicalAction(events[i])
		for j := i + 1; j < len(events); j++ {
			rhs := canonicalAction(events[j])
			key := lhs + "≺" + rhs
			vec[key] += 1.0 / float64(j-i)
		}
	}
	return vec
}

// AffinityCluster clusters traces using cosine similarity between feature
// vectors. threshold controls the minimum similarity required to join an
// existing cluster.
func AffinityCluster(traces []pattern.Sequence, enc func(pattern.Sequence) FeatureVector, threshold float64) []Cluster {
	if enc == nil {
		enc = BagOfNGrams
	}
	if threshold <= 0 {
		threshold = 0.65
	}
	type centroid struct {
		vector  FeatureVector
		count   float64
		cluster *Cluster
	}
	centroids := make([]*centroid, 0)

	for _, trace := range traces {
		vec := enc(trace)
		bestIdx := -1
		bestScore := -1.0

		for idx, c := range centroids {
			score := cosine(vec, c.vector)
			if score > bestScore {
				bestScore = score
				bestIdx = idx
			}
		}

		if bestIdx == -1 || bestScore < threshold {
			clusterID := fmt.Sprintf("cluster-%d", len(centroids)+1)
			cl := &Cluster{
				ID:             clusterID,
				Members:        []string{trace.SessionID},
				Centroid:       copyVector(vec),
				Explanation:    summarizeCluster(trace),
				Representative: trace,
			}
			centroids = append(centroids, &centroid{
				vector:  copyVector(vec),
				count:   1,
				cluster: cl,
			})
			continue
		}

		c := centroids[bestIdx]
		c.cluster.Members = append(c.cluster.Members, trace.SessionID)
		c.count++
		c.vector = incrementalAverage(c.vector, vec, c.count)
		c.cluster.Centroid = copyVector(c.vector)
	}

	out := make([]Cluster, len(centroids))
	for i, c := range centroids {
		sort.Strings(c.cluster.Members)
		out[i] = *c.cluster
	}
	return out
}

func canonicalAction(evt pattern.Event) string {
	return strings.ToLower(evt.ActionFamily + ":" + evt.ActionName + ":" + evt.ResourceClass)
}

func cosine(a, b FeatureVector) float64 {
	var dot, magA, magB float64
	for k, v := range a {
		if bv, ok := b[k]; ok {
			dot += v * bv
		}
		magA += v * v
	}
	for _, v := range b {
		magB += v * v
	}
	if magA == 0 || magB == 0 {
		return 0
	}
	return dot / (math.Sqrt(magA) * math.Sqrt(magB))
}

func incrementalAverage(current FeatureVector, incoming FeatureVector, count float64) FeatureVector {
	out := make(FeatureVector)
	keys := make(map[string]struct{})
	for k := range current {
		keys[k] = struct{}{}
	}
	for k := range incoming {
		keys[k] = struct{}{}
	}
	den := count
	prevDen := count - 1
	if prevDen < 1 {
		prevDen = 1
	}
	for k := range keys {
		prev := current[k]
		newVal := incoming[k]
		out[k] = ((prev * prevDen) + newVal) / den
	}
	return out
}

func summarizeCluster(seq pattern.Sequence) string {
	if len(seq.Events) == 0 {
		return "empty trace"
	}
	first := seq.Events[0]
	last := seq.Events[len(seq.Events)-1]
	return strings.Join([]string{
		"workflow from " + canonicalAction(first) + " to " + canonicalAction(last),
		"principal " + first.PrincipalID,
	}, "; ")
}

func copyVector(src FeatureVector) FeatureVector {
	dst := make(FeatureVector, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
