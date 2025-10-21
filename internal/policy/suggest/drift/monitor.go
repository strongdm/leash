package drift

import (
	"math"
	"sort"
)

// Result summarises drift analysis for a suggestion.
type Result struct {
	PSI             float64
	IsDrift         bool
	TopContributors []Contributor
}

// Contributor highlights which tokens influenced the drift decision.
type Contributor struct {
	Token string
	Value float64
}

// Detect applies a population-stability-index based detector to two
// distributions.
func Detect(expected, observed map[string]float64, threshold float64) Result {
	if threshold <= 0 {
		threshold = 0.25
	}
	psi := PopulationStabilityIndex(expected, observed)
	contributors := topContributors(expected, observed, 5)
	return Result{
		PSI:             psi,
		IsDrift:         psi > threshold,
		TopContributors: contributors,
	}
}

// PopulationStabilityIndex computes the PSI metric between expected and
// observed distributions.
func PopulationStabilityIndex(expected, observed map[string]float64) float64 {
	eps := 1e-6
	keys := make(map[string]struct{})
	for k := range expected {
		keys[k] = struct{}{}
	}
	for k := range observed {
		keys[k] = struct{}{}
	}
	var psi float64
	for k := range keys {
		e := expected[k]
		o := observed[k]
		if e <= 0 {
			e = eps
		}
		if o <= 0 {
			o = eps
		}
		psi += (o - e) * math.Log(o/e)
	}
	return psi
}

func topContributors(expected, observed map[string]float64, limit int) []Contributor {
	type ranked struct {
		token string
		value float64
	}
	items := make([]ranked, 0, len(expected)+len(observed))
	eps := 1e-6
	keys := make(map[string]struct{})
	for k := range expected {
		keys[k] = struct{}{}
	}
	for k := range observed {
		keys[k] = struct{}{}
	}
	for k := range keys {
		e := expected[k]
		o := observed[k]
		if e <= 0 {
			e = eps
		}
		if o <= 0 {
			o = eps
		}
		value := math.Abs((o - e) * math.Log(o/e))
		items = append(items, ranked{token: k, value: value})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].value > items[j].value
	})

	if limit > len(items) {
		limit = len(items)
	}
	out := make([]Contributor, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, Contributor{
			Token: items[i].token,
			Value: items[i].value,
		})
	}
	return out
}
