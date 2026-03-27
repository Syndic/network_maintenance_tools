package audit

import (
	"fmt"
	"sort"

	netbox "network_maintainence_tools/internal/netbox"
)

func DeviceLocations(s netbox.Snapshot) CheckResult {
	var findings []string
	for _, d := range s.Devices {
		if d.Location == nil {
			findings = append(findings, fmt.Sprintf("%s is missing location", d.Name))
		}
	}
	sort.Strings(findings)
	return CheckResult{Name: "Device Locations", Findings: findings}
}
