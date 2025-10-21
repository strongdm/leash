package configstore

import (
	"sort"
	"strings"
)

// EnvLayer represents a single precedence layer of environment variable specifications.
// Later layers override earlier ones when the same key occurs multiple times.
type EnvLayer struct {
	Specs map[string]string
	Order []string
}

func (l EnvLayer) normalizedOrder() []string {
	if len(l.Specs) == 0 {
		return nil
	}
	order := make([]string, 0, len(l.Order)+len(l.Specs))
	seen := make(map[string]struct{})

	for _, key := range l.Order {
		key = trimKey(key)
		if key == "" {
			continue
		}
		if _, ok := l.Specs[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		order = append(order, key)
		seen[key] = struct{}{}
	}

	if len(order) != len(l.Specs) {
		remaining := make([]string, 0, len(l.Specs))
		for key := range l.Specs {
			key = trimKey(key)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			remaining = append(remaining, key)
			seen[key] = struct{}{}
		}
		sort.Strings(remaining)
		order = append(order, remaining...)
	}

	return order
}

func trimKey(key string) string {
	return strings.TrimSpace(key)
}

// MergeEnvLayers applies precedence across multiple EnvLayer values, returning the resulting
// environment variable specifications in deterministic order. Later layers win ties.
func MergeEnvLayers(layers ...EnvLayer) []string {
	if len(layers) == 0 {
		return nil
	}

	orderPerLayer := make([][]string, len(layers))
	finalStage := make(map[string]int)

	for i, layer := range layers {
		order := layer.normalizedOrder()
		orderPerLayer[i] = order
		for _, key := range order {
			if _, ok := layer.Specs[key]; !ok {
				continue
			}
			finalStage[key] = i
		}
	}

	result := make([]string, 0, len(finalStage))
	emitted := make(map[string]struct{})

	for i, order := range orderPerLayer {
		layer := layers[i]
		for _, key := range order {
			if finalStage[key] != i {
				continue
			}
			spec, ok := layer.Specs[key]
			if !ok {
				continue
			}
			if _, already := emitted[key]; already {
				continue
			}
			result = append(result, spec)
			emitted[key] = struct{}{}
		}
	}

	return result
}
