package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditRequiredDeviceFields(s netbox.Snapshot) checkResult {
	var findings []string
	for _, d := range s.Devices {
		if d.Site == nil {
			findings = append(findings, fmt.Sprintf("%s is missing site", d.Name))
		}
		if d.Role.Name == "" {
			findings = append(findings, fmt.Sprintf("%s is missing role", d.Name))
		}
		if d.Status.Value == "" {
			findings = append(findings, fmt.Sprintf("%s is missing status", d.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Required Device Fields", Findings: findings}
}
