package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
	"strings"
)

func auditWirelessNormalization(s netbox.Snapshot, cfg auditConfig) checkResult {
	var findings []string
	for deviceID, ifaces := range s.InterfacesByDevice {
		dev := s.DevicesByID[deviceID]
		if dev.Role.Name == roleAccessPoint || dev.Status.Value == deviceStatusPlanned {
			continue
		}
		wiredComplete := false
		for _, it := range ifaces {
			if isWirelessType(it.Type.Value) {
				continue
			}
			if !it.Enabled {
				continue
			}
			if wiredInterfaceComplete(it, s.IPsByInterface[it.ID]) {
				wiredComplete = true
				break
			}
		}
		for _, it := range ifaces {
			if !isWirelessType(it.Type.Value) || !it.Enabled {
				continue
			}
			if it.Mode != nil && it.UntaggedVLAN != nil && (!cfg.Rules.WirelessNormalization.RequirePrimaryMAC || it.PrimaryMACAddress != nil) {
				continue
			}
			if cfg.Rules.WirelessNormalization.SuppressIfConnectedWiredInterfaceIsComplete && wiredComplete {
				continue
			}
			missing := []string{}
			if cfg.Rules.WirelessNormalization.RequireMode && it.Mode == nil {
				missing = append(missing, "mode")
			}
			if cfg.Rules.WirelessNormalization.RequireUntaggedVLAN && it.UntaggedVLAN == nil {
				missing = append(missing, "untagged_vlan")
			}
			if cfg.Rules.WirelessNormalization.RequirePrimaryMAC && it.PrimaryMACAddress == nil {
				missing = append(missing, "primary_mac_address")
			}
			if len(missing) > 0 {
				findings = append(findings, fmt.Sprintf("%s %s is missing %s", dev.Name, it.Name, strings.Join(missing, ", ")))
			}
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Wireless Normalization", Findings: findings}
}
