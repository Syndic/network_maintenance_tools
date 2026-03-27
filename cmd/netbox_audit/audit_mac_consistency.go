package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
	"strings"
)

func auditMACConsistency(s netbox.Snapshot) checkResult {
	var findings []string
	byMAC := map[string][]netbox.MACAddressRecord{}
	for _, mac := range s.MACAddresses {
		norm := normalizeMAC(mac.MACAddress)
		if norm == "" {
			continue
		}
		byMAC[norm] = append(byMAC[norm], mac)
	}
	for mac, records := range byMAC {
		if len(records) <= 1 {
			continue
		}
		assignments := []string{}
		for _, rec := range records {
			assignments = append(assignments, describeAssignedObject(rec.AssignedObject))
		}
		sort.Strings(assignments)
		findings = append(findings, fmt.Sprintf("MAC %s appears on multiple records: %s", mac, strings.Join(assignments, "; ")))
	}
	for _, it := range s.Interfaces {
		if len(it.MACAddresses) > 1 && it.PrimaryMACAddress == nil {
			findings = append(findings, fmt.Sprintf("%s %s has %d MAC addresses but no primary MAC", it.Device.Name, it.Name, len(it.MACAddresses)))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "MAC Consistency", Findings: findings}
}
