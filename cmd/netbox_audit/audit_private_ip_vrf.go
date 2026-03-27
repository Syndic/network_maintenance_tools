package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditPrivateIPVRF(s netbox.Snapshot, cfg auditConfig) checkResult {
	var findings []string
	for _, ip := range s.IPAddresses {
		addr, ok := bareAddr(ip.Address)
		if !ok {
			continue
		}
		if addr.IsPrivate() {
			if cfg.Rules.PrivateIPVRF.RequireOnPrivateIPs && ip.VRF == nil {
				findings = append(findings, fmt.Sprintf("%s is private but has no VRF", ip.Address))
			}
			continue
		}
		if cfg.Rules.PrivateIPVRF.RequireOnPublicIPs && ip.VRF == nil {
			findings = append(findings, fmt.Sprintf("%s is public but has no VRF", ip.Address))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Private IP VRF Coverage", Findings: findings}
}
