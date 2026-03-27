package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditPatchPanelContinuity(s netbox.Snapshot) checkResult {
	var findings []string
	for _, rp := range s.RearPorts {
		if rp.Cable != nil && len(rp.FrontPorts) == 0 {
			findings = append(findings, fmt.Sprintf("%s rear port %s has a cable but no front-side mapping", rp.Device.Name, rp.Name))
		}
	}
	for _, fp := range s.FrontPorts {
		if fp.Cable != nil && len(fp.RearPorts) == 0 {
			findings = append(findings, fmt.Sprintf("%s front port %s has a cable but no rear-side mapping", fp.Device.Name, fp.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Patch Panel Continuity", Findings: findings}
}
