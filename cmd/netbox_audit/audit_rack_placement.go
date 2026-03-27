package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditRackPlacement(s netbox.Snapshot, cfg auditConfig) checkResult {
	var findings []string
	for _, d := range s.Devices {
		if d.Rack == nil {
			continue
		}
		if cfg.Rules.RackPlacement.ExemptChildDevices && d.ParentDevice != nil {
			continue
		}
		if cfg.isRackTagExempt(d.Tags) {
			continue
		}
		if d.Position == nil {
			findings = append(findings, fmt.Sprintf("%s is in rack %s without a rack position", d.Name, d.Rack.Name))
			continue
		}
		if d.Face == nil || d.Face.Value == "" {
			findings = append(findings, fmt.Sprintf("%s is in rack %s at position %.1f without a face", d.Name, d.Rack.Name, *d.Position))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Rack Placement", Findings: findings}
}
