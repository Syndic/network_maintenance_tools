package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
)

func auditPOEPower(s netbox.Snapshot, cfg auditConfig) checkResult {
	if !cfg.Rules.PoEPower.CheckPoweredDeviceSupply {
		return checkResult{Name: "PoE Power Sufficiency"}
	}
	var findings []string
	for _, it := range s.Interfaces {
		if choiceValue(it.POEMode) != poeModePD || !it.Enabled || len(it.ConnectedEndpoints) == 0 {
			continue
		}
		requiredType := choiceValue(it.POEType)
		matchedPeer := false
		for _, ep := range it.ConnectedEndpoints {
			peer, ok := s.InterfacesByID[ep.ID]
			if !ok {
				continue
			}
			matchedPeer = true
			if cfg.Rules.PoEPower.RequirePSEModeOnPeer && choiceValue(peer.POEMode) != poeModePSE {
				findings = append(findings, fmt.Sprintf("%s %s requires PoE but peer %s %s is not modeled as a PSE interface", it.Device.Name, it.Name, peer.Device.Name, peer.Name))
				continue
			}
			supplyType := choiceValue(peer.POEType)
			ok, reason := poeSupplySufficient(supplyType, requiredType, cfg)
			if !ok {
				if reason == "" {
					reason = "insufficient PoE type"
				}
				findings = append(findings, fmt.Sprintf("%s %s requires %s but is powered by %s %s (%s): %s", it.Device.Name, it.Name, blank(requiredType), peer.Device.Name, peer.Name, blank(supplyType), reason))
			}
		}
		if !matchedPeer {
			findings = append(findings, fmt.Sprintf("%s %s requires PoE but its connected peer interface was not available in the snapshot", it.Device.Name, it.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "PoE Power Sufficiency", Findings: findings}
}
