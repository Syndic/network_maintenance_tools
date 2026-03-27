package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditInterfaceVRF(s netbox.Snapshot, cfg auditConfig) checkResult {
	if !cfg.Rules.InterfaceVRF.RequireOnInterfaces {
		return checkResult{Name: "Interface VRF Coverage"}
	}
	var findings []string
	for _, it := range s.Interfaces {
		dev := s.DevicesByID[it.Device.ID]
		if dev.Status.Value == deviceStatusPlanned || !it.Enabled {
			continue
		}
		if it.VRF != nil {
			continue
		}
		if isWANInterface(it, dev, s.DevicesByID, cfg) {
			continue
		}
		if !(len(it.ConnectedEndpoints) > 0 || len(s.IPsByInterface[it.ID]) > 0 || interfaceHasMAC(it) || it.Mode != nil || it.UntaggedVLAN != nil) {
			continue
		}
		findings = append(findings, fmt.Sprintf("%s %s is missing VRF", dev.Name, it.Name))
	}
	sort.Strings(findings)
	return checkResult{Name: "Interface VRF Coverage", Findings: findings}
}
