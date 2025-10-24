package suggest

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy/suggest/drift"
	"github.com/strongdm/leash/internal/policy/suggest/encoding"
	"github.com/strongdm/leash/internal/policy/suggest/pattern"
	"github.com/strongdm/leash/internal/policy/suggest/scoring"
	"github.com/strongdm/leash/internal/proxy"
)

// Inputs captures the raw policy artefacts the suggestion engine can analyse.
type Inputs struct {
	LSMPolicies    *lsm.PolicySet
	HTTPRewrites   []proxy.HeaderRewriteRule
	EventSequences []pattern.Sequence
	// Future: Cedar AST, MCP descriptors, etc.
}

// Analyze runs the mechanical suggestion passes and returns a consolidated
// result. Callers can provide nil inputs; the engine will simply skip the
// corresponding passes.
func Analyze(inputs Inputs, opts Options) Result {
	defaults := DefaultOptions()
	if opts.MinDirectoryGroup <= 0 {
		opts.MinDirectoryGroup = defaults.MinDirectoryGroup
	}
	if opts.MinDomainGroup <= 0 {
		opts.MinDomainGroup = defaults.MinDomainGroup
	}
	if opts.MinHTTPGroup <= 0 {
		opts.MinHTTPGroup = defaults.MinHTTPGroup
	}
	if opts.MinSequenceSupport <= 0 {
		opts.MinSequenceSupport = defaults.MinSequenceSupport
	}
	if opts.MaxSequenceLength <= 0 {
		opts.MaxSequenceLength = defaults.MaxSequenceLength
	}
	if opts.ClusterSimilarity <= 0 {
		opts.ClusterSimilarity = defaults.ClusterSimilarity
	}
	if opts.SessionWindow <= 0 {
		opts.SessionWindow = defaults.SessionWindow
	}
	if opts.DriftThreshold <= 0 {
		opts.DriftThreshold = defaults.DriftThreshold
	}
	if opts.TailLimit == 0 {
		opts.TailLimit = defaults.TailLimit
	}
	if opts.MaxClusters <= 0 {
		opts.MaxClusters = defaults.MaxClusters
	}
	if opts.MinClusterSize <= 0 {
		opts.MinClusterSize = defaults.MinClusterSize
	}

	suggestions := make([]Suggestion, 0)

	if inputs.LSMPolicies != nil {
		suggestions = append(suggestions, directorySuggestions(inputs.LSMPolicies, opts)...)
		suggestions = append(suggestions, domainSuggestions(inputs.LSMPolicies, opts)...)
	}

	if len(inputs.HTTPRewrites) > 0 {
		suggestions = append(suggestions, httpSuggestions(inputs.HTTPRewrites, opts)...)
	}

	if len(inputs.EventSequences) > 0 {
		suggestions = append(suggestions, workflowSuggestions(inputs.EventSequences, opts)...)
	}

	sort.SliceStable(suggestions, func(i, j int) bool {
		if suggestions[i].Kind == suggestions[j].Kind {
			return suggestions[i].PolicyCount > suggestions[j].PolicyCount
		}
		return suggestions[i].Kind < suggestions[j].Kind
	})

	return Result{Suggestions: suggestions}
}

// directorySuggestions groups file policies by directory and effect.
func directorySuggestions(ps *lsm.PolicySet, opts Options) []Suggestion {
	type key struct {
		dir    string
		effect string
	}
	buckets := make(map[key]*dirBucket)

	addRule := func(rule lsm.PolicyRule, opName string) {
		path := strings.TrimSpace(rulePath(&rule))
		if path == "" {
			return
		}
		// Skip explicit directory rules; they already use Dir::.
		if rule.IsDirectory == 1 {
			return
		}
		dir := filepath.Clean(filepath.Dir(path))
		if dir == "." || dir == "" {
			dir = "/"
		}
		effect := effectString(rule.Action)
		bucket := buckets[key{dir: dir, effect: effect}]
		if bucket == nil {
			bucket = newDirBucket(dir, effect)
			buckets[key{dir: dir, effect: effect}] = bucket
		}
		bucket.addRule(rule, opName)
	}

	for _, rule := range ps.Open {
		addRule(rule, operationName(rule.Operation))
	}
	// Exec policies have exact paths; we do not currently suggest grouping them
	// by directory because exec control is typically more precise.

	suggestions := make([]Suggestion, 0)
	for _, bucket := range buckets {
		if bucket.count < opts.MinDirectoryGroup {
			continue
		}
		if len(bucket.targets) <= 1 {
			continue
		}
		suggestions = append(suggestions, bucket.toSuggestion())
	}
	return suggestions
}

type dirBucket struct {
	dir        string
	effect     string
	count      int
	operations map[string]struct{}
	targets    map[string]struct{}
	refs       []PolicyReference
}

func newDirBucket(dir, effect string) *dirBucket {
	return &dirBucket{
		dir:        dir,
		effect:     effect,
		operations: make(map[string]struct{}),
		targets:    make(map[string]struct{}),
		refs:       make([]PolicyReference, 0),
	}
}

func (b *dirBucket) addRule(rule lsm.PolicyRule, opName string) {
	b.count++
	b.operations[opName] = struct{}{}
	target := strings.TrimSpace(rulePath(&rule))
	b.targets[target] = struct{}{}
	b.refs = append(b.refs, PolicyReference{
		Effect:    b.effect,
		Operation: opName,
		Target:    target,
		Source:    "lsm",
	})
}

func (b *dirBucket) toSuggestion() Suggestion {
	ops := make([]string, 0, len(b.operations))
	for opName := range b.operations {
		ops = append(ops, opName)
	}
	sort.Strings(ops)

	proposed := buildDirectoryCedar(b.effect, b.dir, ops)
	summary := b.effectTitle() + " " + strings.Join(ops, ", ") + " in directory " + b.dir
	return Suggestion{
		Kind:          SuggestDirectory,
		Summary:       summary,
		ProposedCedar: proposed,
		PolicyCount:   b.count,
		Confidence:    confidenceFromCounts(len(b.targets), b.count),
		PolicyRefs:    b.refs,
		Metadata: map[string]string{
			"directory": b.dir,
		},
	}
}

func (b *dirBucket) effectTitle() string {
	if b.effect == "permit" {
		return "Allow"
	}
	return "Deny"
}

// domainSuggestions groups connect rules by shared base domain.
func domainSuggestions(ps *lsm.PolicySet, opts Options) []Suggestion {
	type key struct {
		base   string
		effect string
		port   uint16
	}
	buckets := make(map[key]*domainBucket)

	for _, rule := range ps.Connect {
		host := strings.TrimSpace(connectHostname(&rule))
		if host == "" {
			continue
		}
		base, ok := baseDomain(host)
		if !ok {
			continue
		}
		effect := effectString(rule.Action)
		k := key{base: base, effect: effect, port: rule.DestPort}
		bucket := buckets[k]
		if bucket == nil {
			bucket = newDomainBucket(base, effect, rule.DestPort)
			buckets[k] = bucket
		}
		bucket.addRule(rule)
	}

	suggestions := make([]Suggestion, 0)
	for _, bucket := range buckets {
		if bucket.count < opts.MinDomainGroup {
			continue
		}
		suggestions = append(suggestions, bucket.toSuggestion())
	}
	return suggestions
}

type domainBucket struct {
	base   string
	effect string
	port   uint16
	count  int
	hosts  map[string]struct{}
	refs   []PolicyReference
}

func newDomainBucket(base, effect string, port uint16) *domainBucket {
	return &domainBucket{
		base:   base,
		effect: effect,
		port:   port,
		hosts:  make(map[string]struct{}),
		refs:   make([]PolicyReference, 0),
	}
}

func (b *domainBucket) addRule(rule lsm.PolicyRule) {
	b.count++
	host := strings.TrimSpace(connectHostname(&rule))
	b.hosts[host] = struct{}{}
	md := map[string]string{}
	if rule.DestPort > 0 {
		md["port"] = fmt.Sprintf("%d", rule.DestPort)
	}
	if rule.HostnameLen == 0 && rule.DestIP != 0 {
		md["ip"] = ipString(rule.DestIP)
	}
	b.refs = append(b.refs, PolicyReference{
		Effect:    effectString(rule.Action),
		Operation: operationName(rule.Operation),
		Target:    host,
		Source:    "lsm",
		Metadata:  md,
	})
}

func (b *domainBucket) toSuggestion() Suggestion {
	wildcard := "*." + b.base
	resource := fmt.Sprintf("Host::\"%s\"", wildcard)
	proposed := fmt.Sprintf("%s (principal, action == Action::\"NetworkConnect\", resource == %s);", b.effect, resource)
	summary := fmt.Sprintf("%s network connect to *.%s", strings.Title(b.effect), b.base)
	md := map[string]string{"base_domain": b.base}
	if b.port > 0 {
		md["port"] = fmt.Sprintf("%d", b.port)
	}
	return Suggestion{
		Kind:          SuggestDomain,
		Summary:       summary,
		ProposedCedar: proposed,
		PolicyCount:   b.count,
		Confidence:    confidenceFromCounts(len(b.hosts), b.count),
		PolicyRefs:    b.refs,
		Metadata:      md,
	}
}

// httpSuggestions groups header rewrite rules by host base domain.
func httpSuggestions(rules []proxy.HeaderRewriteRule, opts Options) []Suggestion {
	type key struct {
		base string
	}
	buckets := make(map[key]*httpBucket)

	for _, rule := range rules {
		base, ok := baseDomain(rule.Host)
		if !ok {
			continue
		}
		k := key{base: base}
		bucket := buckets[k]
		if bucket == nil {
			bucket = newHTTPBucket(base)
			buckets[k] = bucket
		}
		bucket.addRule(rule)
	}

	suggestions := make([]Suggestion, 0)
	for _, bucket := range buckets {
		if bucket.count < opts.MinHTTPGroup {
			continue
		}
		suggestions = append(suggestions, bucket.toSuggestion())
	}
	return suggestions
}

type httpBucket struct {
	base  string
	count int
	hosts map[string]struct{}
	refs  []PolicyReference
}

func newHTTPBucket(base string) *httpBucket {
	return &httpBucket{
		base:  base,
		hosts: make(map[string]struct{}),
		refs:  make([]PolicyReference, 0),
	}
}

func (b *httpBucket) addRule(rule proxy.HeaderRewriteRule) {
	b.count++
	b.hosts[rule.Host] = struct{}{}
	md := map[string]string{
		"header": rule.Header,
		"value":  rule.Value,
	}
	b.refs = append(b.refs, PolicyReference{
		Effect:    "permit",
		Operation: "http.rewrite",
		Target:    rule.Host,
		Source:    "http",
		Metadata:  md,
	})
}

func (b *httpBucket) toSuggestion() Suggestion {
	// Emit concrete, transpiler-valid Cedar for each observed rewrite under this base domain.
	// We cannot yet compile wildcard rewrite rules, and header/value are per-rule, so
	// generate one statement per (host, header, value) reference for now.
	// This guarantees ProposedCedar parses and produces HeaderRewriteRule entries.
	if len(b.refs) == 0 {
		return Suggestion{Kind: SuggestHTTPHost, Summary: "No HTTP rewrite samples"}
	}

	type key struct{ host, header, value string }
	uniq := make(map[key]struct{})
	pairs := make([]key, 0, len(b.refs))
	for _, r := range b.refs {
		h := strings.TrimSpace(r.Target)
		header := strings.TrimSpace(r.Metadata["header"])
		value := strings.TrimSpace(r.Metadata["value"])
		if h == "" || header == "" || value == "" {
			continue
		}
		k := key{host: h, header: header, value: value}
		if _, seen := uniq[k]; !seen {
			uniq[k] = struct{}{}
			pairs = append(pairs, k)
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].host == pairs[j].host {
			if pairs[i].header == pairs[j].header {
				return pairs[i].value < pairs[j].value
			}
			return pairs[i].header < pairs[j].header
		}
		return pairs[i].host < pairs[j].host
	})
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString("permit (principal, action == Action::\"HttpRewrite\", resource == Host::\"")
		sb.WriteString(p.host)
		sb.WriteString("\") when { context.header == \"")
		sb.WriteString(p.header)
		sb.WriteString("\" && context.value == \"")
		sb.WriteString(p.value)
		sb.WriteString("\" };")
		sb.WriteByte('\n')
	}
	proposed := strings.TrimSpace(sb.String())
	summary := "Consolidate HTTP rewrites for *." + b.base
	return Suggestion{
		Kind:          SuggestHTTPHost,
		Summary:       summary,
		ProposedCedar: proposed,
		PolicyCount:   b.count,
		Confidence:    confidenceFromCounts(len(b.hosts), b.count),
		PolicyRefs:    b.refs,
		Metadata: map[string]string{
			"base_domain": b.base,
		},
	}
}

func workflowSuggestions(seqs []pattern.Sequence, opts Options) []Suggestion {
	filtered := make([]pattern.Sequence, 0, len(seqs))
	seqIndex := make(map[string]pattern.Sequence, len(seqs))
	for _, seq := range seqs {
		if len(seq.Events) == 0 {
			continue
		}
		sort.SliceStable(seq.Events, func(i, j int) bool {
			return seq.Events[i].Timestamp.Before(seq.Events[j].Timestamp)
		})
		filtered = append(filtered, seq)
		seqIndex[seq.SessionID] = seq
	}
	if len(filtered) == 0 {
		return nil
	}

	clusters := encoding.AffinityCluster(filtered, encoding.BagOfNGrams, opts.ClusterSimilarity)
	if len(clusters) == 0 {
		return nil
	}

	sort.SliceStable(clusters, func(i, j int) bool {
		return len(clusters[i].Members) > len(clusters[j].Members)
	})

	allPrincipals := principalSet(filtered)
	overallDist := eventDistribution(filtered)
	scorer := scoring.IntensityScorer{
		HalfLife:           opts.SessionWindow,
		Floor:              0.1,
		Cap:                1.0,
		ObservationHorizon: opts.SessionWindow * 12,
	}

	suggestions := make([]Suggestion, 0, len(clusters))
	for _, cl := range clusters {
		clusterSeqs := make([]pattern.Sequence, 0, len(cl.Members))
		for _, id := range cl.Members {
			if seq, ok := seqIndex[id]; ok {
				clusterSeqs = append(clusterSeqs, seq)
			}
		}
		if len(clusterSeqs) < opts.MinClusterSize {
			continue
		}

		cfg := pattern.DefaultConfig()
		cfg.MinSupport = opts.MinSequenceSupport
		cfg.MaxLength = opts.MaxSequenceLength
		cfg.TargetActions = deriveTargetActions(clusterSeqs)
		patterns := pattern.Mine(clusterSeqs, cfg)
		if len(patterns) == 0 {
			continue
		}

		clusterPrincipals := principalSet(clusterSeqs)
		coverageScore, recencyScore := scorer.Score(buildTimeSeries(clusterSeqs, opts.SessionWindow), len(clusterPrincipals), len(allPrincipals))
		confidence := math.Min(1.0, math.Max(0.1, (coverageScore+recencyScore)/2))

		topPattern := patterns[0]
		clusterDist := eventDistribution(clusterSeqs)
		driftResult := drift.Detect(overallDist, clusterDist, opts.DriftThreshold)

		metadata := map[string]string{
			"cluster_id":      cl.ID,
			"session_count":   strconv.Itoa(len(cl.Members)),
			"principal_count": strconv.Itoa(len(clusterPrincipals)),
			"coverage_score":  fmt.Sprintf("%.3f", coverageScore),
			"recency_score":   fmt.Sprintf("%.3f", recencyScore),
			"confidence":      fmt.Sprintf("%.3f", confidence),
			"top_pattern":     strings.Join(topPattern.Tokens, " -> "),
			"top_support":     strconv.Itoa(topPattern.Support),
			"psi":             fmt.Sprintf("%.3f", driftResult.PSI),
			"drift_flag":      strconv.FormatBool(driftResult.IsDrift),
		}
		if len(topPattern.Sessions) > 0 {
			metadata["support_sessions"] = strings.Join(topPattern.Sessions, ",")
		}

		refs := samplePolicyRefs(clusterSeqs, 4)

		suggestions = append(suggestions, Suggestion{
			Kind:        SuggestWorkflow,
			Summary:     fmt.Sprintf("Workflow %s (%d sessions)", cl.ID, len(cl.Members)),
			PolicyCount: len(cl.Members),
			Confidence:  confidence,
			PolicyRefs:  refs,
			Metadata:    metadata,
		})

		if opts.MaxClusters > 0 && len(suggestions) >= opts.MaxClusters {
			break
		}
	}

	sort.SliceStable(suggestions, func(i, j int) bool {
		return suggestions[i].PolicyCount > suggestions[j].PolicyCount
	})

	return suggestions
}

func principalSet(seqs []pattern.Sequence) map[string]struct{} {
	out := make(map[string]struct{})
	for _, seq := range seqs {
		if seq.Principal != "" {
			out[seq.Principal] = struct{}{}
			continue
		}
		if len(seq.Events) > 0 {
			if pid := seq.Events[0].PrincipalID; pid != "" {
				out[pid] = struct{}{}
			}
		}
	}
	return out
}

func buildTimeSeries(seqs []pattern.Sequence, window time.Duration) []scoring.TimeSeriesPoint {
	if window <= 0 {
		window = time.Minute
	}
	buckets := make(map[time.Time]float64)
	for _, seq := range seqs {
		for _, evt := range seq.Events {
			if evt.Timestamp.IsZero() {
				continue
			}
			key := evt.Timestamp.Truncate(window)
			buckets[key]++
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	points := make([]scoring.TimeSeriesPoint, 0, len(buckets))
	for ts, count := range buckets {
		points = append(points, scoring.TimeSeriesPoint{Timestamp: ts, Count: count})
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})
	return points
}

func eventDistribution(seqs []pattern.Sequence) map[string]float64 {
	counts := make(map[string]float64)
	total := 0.0
	for _, seq := range seqs {
		for _, evt := range seq.Events {
			token := canonicalEventToken(evt)
			counts[token]++
			total++
		}
	}
	if total == 0 {
		return counts
	}
	for k, v := range counts {
		counts[k] = v / total
	}
	return counts
}

func canonicalEventToken(evt pattern.Event) string {
	family := evt.ActionFamily
	if family == "" {
		family = "unknown"
	}
	action := evt.ActionName
	if action == "" {
		action = "event"
	}
	resource := evt.ResourceClass
	if resource == "" {
		resource = "resource"
	}
	facet := evt.ResourceFacet
	if facet == "" {
		facet = "*"
	}
	return strings.ToLower(strings.Join([]string{family, action, resource, facet}, ":"))
}

func deriveTargetActions(seqs []pattern.Sequence) []string {
	targets := make(map[string]struct{})
	for _, seq := range seqs {
		for _, evt := range seq.Events {
			if evt.ActionName == "" {
				continue
			}
			lower := strings.ToLower(evt.ActionName)
			if evt.ActionFamily == "network" || evt.ActionFamily == "http" || evt.ActionFamily == "process" || len(seq.Events) <= 1 {
				targets[lower] = struct{}{}
			}
		}
		if len(seq.Events) > 0 {
			last := strings.ToLower(seq.Events[len(seq.Events)-1].ActionName)
			if last != "" {
				targets[last] = struct{}{}
			}
		}
	}
	if len(targets) == 0 {
		targets["connect"] = struct{}{}
	}
	result := make([]string, 0, len(targets))
	for k := range targets {
		result = append(result, k)
	}
	sort.Strings(result)
	if len(result) > 6 {
		result = result[:6]
	}
	return result
}

func samplePolicyRefs(seqs []pattern.Sequence, limit int) []PolicyReference {
	if limit <= 0 {
		limit = 3
	}
	refs := make([]PolicyReference, 0, limit)
	for _, seq := range seqs {
		if len(seq.Events) == 0 {
			continue
		}
		evt := seq.Events[len(seq.Events)-1]
		effect := strings.ToLower(evt.Outcome)
		if effect == "" {
			effect = "permit"
		}
		md := map[string]string{
			"session":       seq.SessionID,
			"principal":     seq.Principal,
			"resource":      evt.ResourceClass,
			"resourceFacet": evt.ResourceFacet,
		}
		refs = append(refs, PolicyReference{
			Effect:    effect,
			Operation: evt.ActionName,
			Target:    evt.ResourceFacet,
			Source:    "ring",
			Metadata:  md,
		})
		if len(refs) >= limit {
			break
		}
	}
	return refs
}

// Helpers -----------------------------------------------------------------

func rulePath(rule *lsm.PolicyRule) string {
	return string(bytes.TrimRight(rule.Path[:rule.PathLen], "\x00"))
}

func connectHostname(rule *lsm.PolicyRule) string {
	if rule.HostnameLen > 0 {
		return string(rule.Hostname[:rule.HostnameLen])
	}
	if rule.DestIP != 0 {
		return ipString(rule.DestIP)
	}
	return ""
}

func ipString(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

func effectString(action int32) string {
	if action == lsm.PolicyAllow {
		return "permit"
	}
	return "forbid"
}

func operationName(op int32) string {
	switch op {
	case lsm.OpOpen:
		return "open"
	case lsm.OpOpenRO:
		return "read"
	case lsm.OpOpenRW:
		return "write"
	case lsm.OpExec:
		return "exec"
	case lsm.OpConnect:
		return "connect"
	default:
		return "unknown"
	}
}

func buildDirectoryCedar(effect, dir string, ops []string) string {
	actionClause := buildActionClause(ops)
	return fmt.Sprintf("%s (principal, %s, resource) when { resource in [ Dir::\"%s\" ] };", effect, actionClause, dir)
}

func buildActionClause(ops []string) string {
	if len(ops) == 0 {
		return "action == Action::\"FileOpen\""
	}
	if len(ops) == 1 {
		return fmt.Sprintf("action == Action::\"%s\"", operationToAction(ops[0]))
	}
	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, fmt.Sprintf("Action::\"%s\"", operationToAction(op)))
	}
	return fmt.Sprintf("action in [%s]", strings.Join(parts, ", "))
}

func operationToAction(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "open":
		return "FileOpen"
	case "read":
		return "FileOpenReadOnly"
	case "write":
		return "FileOpenReadWrite"
	case "exec":
		return "ProcessExec"
	case "connect":
		return "NetworkConnect"
	default:
		return op
	}
}

func confidenceFromCounts(uniqueTargets, total int) float64 {
	if total == 0 {
		return 0
	}
	// Simple heuristic: more unique targets per suggestion => higher
	// confidence, but keep within [0.1, 1.0].
	ratio := float64(uniqueTargets) / float64(total)
	if ratio < 0.1 {
		ratio = 0.1
	}
	if ratio > 1.0 {
		ratio = 1.0
	}
	return ratio
}

func baseDomain(host string) (string, bool) {
	clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "*.")
	if clean == "" {
		return "", false
	}
	labels := strings.Split(clean, ".")
	if len(labels) < 2 {
		return "", false
	}
	base := strings.Join(labels[len(labels)-2:], ".")
	if base == "" {
		return "", false
	}
	return base, true
}
