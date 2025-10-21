package scoring

import (
	"math"
	"sort"
	"time"
)

// TimeSeriesPoint represents aggregated support for a suggestion in a given
// bucket.
type TimeSeriesPoint struct {
	Timestamp time.Time
	Count     float64
}

// IntensityScorer estimates coverage and recency using an exponential decay
// kernel inspired by Hawkes processes.
type IntensityScorer struct {
	HalfLife           time.Duration
	Floor              float64
	Cap                float64
	ObservationHorizon time.Duration
}

// Score returns (coverageScore, recencyScore). coverageScore captures fraction
// of principals or sessions covered; recencyScore reflects decayed intensity
// over the observation window.
func (s IntensityScorer) Score(series []TimeSeriesPoint, coverage, population int) (float64, float64) {
	if s.HalfLife <= 0 {
		s.HalfLife = 30 * time.Minute
	}
	if s.Floor <= 0 {
		s.Floor = 0.1
	}
	if s.Cap <= 0 {
		s.Cap = 1.0
	}
	if s.ObservationHorizon <= 0 {
		s.ObservationHorizon = 6 * time.Hour
	}

	if population <= 0 {
		population = 1
	}
	coverageScore := float64(coverage) / float64(population)
	if coverageScore > s.Cap {
		coverageScore = s.Cap
	}
	if coverageScore < s.Floor {
		coverageScore = s.Floor
	}

	if len(series) == 0 {
		return coverageScore, s.Floor
	}

	points := append([]TimeSeriesPoint{}, series...)
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})

	decay := math.Ln2 / s.HalfLife.Seconds()
	var intensity float64
	end := points[len(points)-1].Timestamp
	horizonStart := end.Add(-s.ObservationHorizon)

	for _, pt := range points {
		if pt.Timestamp.Before(horizonStart) {
			continue
		}
		delta := end.Sub(pt.Timestamp).Seconds()
		intensity += pt.Count * math.Exp(-decay*delta)
	}

	// Normalize to [Floor, Cap] using logistic squashing.
	recencyScore := 1 / (1 + math.Exp(-intensity))
	if recencyScore < s.Floor {
		recencyScore = s.Floor
	}
	if recencyScore > s.Cap {
		recencyScore = s.Cap
	}
	return coverageScore, recencyScore
}
