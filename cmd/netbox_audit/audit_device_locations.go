package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditDeviceLocations(s netbox.Snapshot) checkResult {
	var findings []string
	for _, d := range s.Devices {
		if d.Location == nil {
			findings = append(findings, fmt.Sprintf("%s is missing location", d.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Device Locations", Findings: findings}
}
