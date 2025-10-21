package scoring

import (
	"testing"
	"time"
)

func TestIntensityScorerIncreasesWithRecentCounts(t *testing.T) {
	now := time.Now()
	series := []TimeSeriesPoint{
		{Timestamp: now.Add(-2 * time.Hour), Count: 1},
		{Timestamp: now.Add(-30 * time.Minute), Count: 3},
	}

	scorer := IntensityScorer{
		HalfLife:           time.Hour,
		ObservationHorizon: 3 * time.Hour,
	}

	coverage, recency := scorer.Score(series, 8, 10)
	if coverage <= 0.7 {
		t.Fatalf("expected coverage above 0.7, got %f", coverage)
	}
	if recency <= 0.3 {
		t.Fatalf("expected non-trivial recency, got %f", recency)
	}
}
