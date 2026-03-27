package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditIPVLANConsistency(s netbox.Snapshot) checkResult {
	prefixes := parsePrefixes(s.Prefixes)
	var findings []string
	for _, ip := range s.IPAddresses {
		if ip.AssignedObjectType != netbox.ObjectTypeInterface {
			continue
		}
		it, ok := s.InterfacesByID[ip.AssignedObjectID]
		if !ok || it.Mode == nil || it.Mode.Value != vlanModeAccess || it.UntaggedVLAN == nil {
			continue
		}
		addr, ok := bareAddr(ip.Address)
		if !ok {
			continue
		}
		match := bestPrefixMatch(prefixes, addr, vrfID(ip.VRF))
		if match == nil || match.VLAN == nil {
			continue
		}
		if match.VLAN.ID != it.UntaggedVLAN.ID {
			findings = append(findings, fmt.Sprintf("%s %s carries %s but access VLAN is %s and best prefix VLAN is %s", s.DevicesByID[it.Device.ID].Name, it.Name, ip.Address, it.UntaggedVLAN.Name, match.VLAN.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "IP / VLAN Consistency", Findings: findings}
}
