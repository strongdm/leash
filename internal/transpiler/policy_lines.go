package transpiler

import (
	"sort"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func cloneAndSortPolicyRules(policies *lsm.PolicySet) (openRules, execRules, connectRules []lsm.PolicyRule) {
	openRules = append([]lsm.PolicyRule(nil), policies.Open...)
	execRules = append([]lsm.PolicyRule(nil), policies.Exec...)
	connectRules = append([]lsm.PolicyRule(nil), policies.Connect...)

	sort.SliceStable(openRules, func(i, j int) bool {
		if openRules[i].PathLen == openRules[j].PathLen {
			return openRules[i].String() < openRules[j].String()
		}
		return openRules[i].PathLen > openRules[j].PathLen
	})

	sort.SliceStable(execRules, func(i, j int) bool {
		if execRules[i].PathLen == execRules[j].PathLen {
			return execRules[i].String() < execRules[j].String()
		}
		return execRules[i].PathLen > execRules[j].PathLen
	})

	sort.SliceStable(connectRules, func(i, j int) bool {
		if connectRules[i].HostnameLen == connectRules[j].HostnameLen {
			return connectRules[i].String() < connectRules[j].String()
		}
		return connectRules[i].HostnameLen > connectRules[j].HostnameLen
	})

	return
}

func PolicySetToLines(policies *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) []string {
	if policies == nil {
		policies = &lsm.PolicySet{}
	}

	openRules, execRules, connectRules := cloneAndSortPolicyRules(policies)
	rewriteRules := append([]proxy.HeaderRewriteRule(nil), httpRules...)

	sort.SliceStable(rewriteRules, func(i, j int) bool {
		return rewriteRules[i].String() < rewriteRules[j].String()
	})

	total := len(openRules) + len(execRules) + len(connectRules) + len(rewriteRules)
	if policies.ConnectDefaultExplicit {
		total++
	}
	if total == 0 {
		return nil
	}

	lines := make([]string, 0, total)

	for _, rule := range openRules {
		lines = append(lines, rule.String())
	}

	for _, rule := range execRules {
		lines = append(lines, rule.String())
	}

	if policies.ConnectDefaultExplicit {
		if policies.ConnectDefaultAllow {
			lines = append(lines, "default net.send allow")
		} else {
			lines = append(lines, "default net.send deny")
		}
	}

	for _, rule := range connectRules {
		lines = append(lines, rule.String())
	}

	for _, rule := range rewriteRules {
		lines = append(lines, rule.String())
	}

	return lines
}
