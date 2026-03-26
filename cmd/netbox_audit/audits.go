package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

func auditRequiredDeviceFields(s snapshot) checkResult {
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

func auditDeviceLocations(s snapshot) checkResult {
	var findings []string
	for _, d := range s.Devices {
		if d.Location == nil {
			findings = append(findings, fmt.Sprintf("%s is missing location", d.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Device Locations", Findings: findings}
}

func auditParentPlacement(s snapshot) checkResult {
	deviceByID := map[int]device{}
	for _, d := range s.Devices {
		deviceByID[d.ID] = d
	}
	var findings []string
	for _, d := range s.Devices {
		if d.ParentDevice == nil {
			continue
		}
		parent, ok := deviceByID[d.ParentDevice.ID]
		if !ok {
			findings = append(findings, fmt.Sprintf("%s references missing parent device id=%d", d.Name, d.ParentDevice.ID))
			continue
		}
		if d.Site != nil && parent.Site != nil && d.Site.ID != parent.Site.ID {
			findings = append(findings, fmt.Sprintf("%s site %s differs from parent %s site %s", d.Name, d.Site.Name, parent.Name, parent.Site.Name))
		}
		switch {
		case d.Rack == nil && parent.Rack != nil:
			findings = append(findings, fmt.Sprintf("%s is missing rack while parent %s is in rack %s", d.Name, parent.Name, parent.Rack.Name))
		case d.Rack != nil && parent.Rack == nil:
			findings = append(findings, fmt.Sprintf("%s is in rack %s while parent %s has no rack", d.Name, d.Rack.Name, parent.Name))
		case d.Rack != nil && parent.Rack != nil && d.Rack.ID != parent.Rack.ID:
			findings = append(findings, fmt.Sprintf("%s rack %s differs from parent %s rack %s", d.Name, d.Rack.Name, parent.Name, parent.Rack.Name))
		}
		if d.Location != nil && parent.Location != nil && d.Location.ID != parent.Location.ID {
			findings = append(findings, fmt.Sprintf("%s location %s differs from parent %s location %s", d.Name, d.Location.Name, parent.Name, parent.Location.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Parent Placement Consistency", Findings: findings}
}

func auditRackPlacement(s snapshot, cfg auditConfig) checkResult {
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

func auditDeviceTypeDrift(s snapshot) checkResult {
	modsByDevice := make(map[int][]module)
	for _, m := range s.Modules {
		modsByDevice[m.Device.ID] = append(modsByDevice[m.Device.ID], m)
	}

	checks := []componentDriftCheck{
		newInterfaceDriftCheck(s.InterfaceTemplates, s.Interfaces),
		newTypedDriftCheck("Console ports", s.ConsolePortTemplates, s.ConsolePorts),
		newTypedDriftCheck("Console server ports", s.ConsoleServerPortTemplates, s.ConsoleServerPorts),
		newTypedDriftCheck("Power ports", s.PowerPortTemplates, s.PowerPorts),
		newTypedDriftCheck("Power outlets", s.PowerOutletTemplates, s.PowerOutlets),
		newTypedDriftCheck("Front ports", frontTemplatesToTyped(s.FrontPortTemplates), frontPortsToTyped(s.FrontPorts)),
		newTypedDriftCheck("Rear ports", rearTemplatesToTyped(s.RearPortTemplates), rearPortsToTyped(s.RearPorts)),
		newNamedDriftCheck("Device bays", s.DeviceBayTemplates, s.DeviceBays),
		newNamedDriftCheck("Module bays", s.ModuleBayTemplates, moduleBaysToNamed(s.ModuleBays)),
	}

	var drifts []driftRecord
	for _, d := range s.Devices {
		var details []string
		for _, check := range checks {
			expected := check.expectedForDevice(d.DeviceType.ID, modsByDevice[d.ID])
			actual := check.actualByDevice[d.ID]
			checkDetails := compareComponentMaps(check.label, expected, actual, check.diffSpec)
			details = append(details, checkDetails...)
		}
		if len(details) > 0 {
			drifts = append(drifts, driftRecord{Device: d.Name, Model: d.DeviceType.Model, Details: details})
		}
	}
	sort.Slice(drifts, func(i, j int) bool { return drifts[i].Device < drifts[j].Device })
	var findings []string
	if len(drifts) > 0 {
		findings = []string{fmt.Sprintf("%d devices drift from their expected components", len(drifts))}
	}
	return checkResult{Name: "Device Type Drift", Findings: findings, Extra: drifts}
}

func auditHoneypots(s snapshot) checkResult {
	var honeypots []ipAddress
	for _, ip := range s.IPAddresses {
		if hasTag(ip.Tags, tagHoneypot) {
			honeypots = append(honeypots, ip)
		}
	}

	prefixes := make([]prefix, 0, len(s.Prefixes))
	for _, p := range s.Prefixes {
		if p.VLAN != nil {
			prefixes = append(prefixes, p)
		}
	}

	var findings []string
	for _, p := range prefixes {
		prefixNet, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			findings = append(findings, fmt.Sprintf("prefix %s could not be parsed while checking honeypot coverage", p.Prefix))
			continue
		}

		found := false
		for _, ip := range honeypots {
			if vrfID(ip.VRF) != vrfID(p.VRF) {
				continue
			}
			addr, ok := bareAddr(ip.Address)
			if !ok {
				continue
			}
			if prefixNet.Contains(addr) {
				found = true
				break
			}
		}
		if !found {
			findings = append(findings, fmt.Sprintf("%s (%s) has no honeypot IP", p.Prefix, p.VLAN.Name))
		}
	}

	for _, ip := range honeypots {
		addr, ok := bareAddr(ip.Address)
		if !ok {
			findings = append(findings, fmt.Sprintf("%s is tagged honeypot but could not be parsed", ip.Address))
			continue
		}

		matched := false
		for _, p := range prefixes {
			if vrfID(ip.VRF) != vrfID(p.VRF) {
				continue
			}
			prefixNet, err := netip.ParsePrefix(p.Prefix)
			if err != nil {
				continue
			}
			if prefixNet.Contains(addr) {
				matched = true
				break
			}
		}
		if !matched {
			findings = append(findings, fmt.Sprintf("%s is tagged honeypot but is not inside any VLAN-backed prefix", ip.Address))
		}
	}

	sort.Strings(findings)
	return checkResult{Name: "Honeypot Coverage", Findings: findings}
}

func newInterfaceDriftCheck(templates []interfaceTemplate, instances []iface) componentDriftCheck {
	byDT := map[int]map[string]componentSpec{}
	byMT := map[int]map[string]componentSpec{}
	for _, t := range templates {
		spec := componentSpec{
			Type:     t.Type.Value,
			MgmtOnly: boolPtr(t.MgmtOnly),
			POEMode:  choiceValue(t.POEMode),
			POEType:  choiceValue(t.POEType),
			Enabled:  boolPtr(t.Enabled),
		}
		if t.DeviceType != nil {
			ensureComponentMap(byDT, t.DeviceType.ID)[t.Name] = spec
		}
		if t.ModuleType != nil {
			ensureComponentMap(byMT, t.ModuleType.ID)[t.Name] = spec
		}
	}
	actual := map[int]map[string]componentSpec{}
	for _, it := range instances {
		ensureComponentMap(actual, it.Device.ID)[it.Name] = componentSpec{
			Type:     it.Type.Value,
			MgmtOnly: boolPtr(it.MgmtOnly),
			POEMode:  choiceValue(it.POEMode),
			POEType:  choiceValue(it.POEType),
			Enabled:  boolPtr(it.Enabled),
		}
	}
	return componentDriftCheck{
		label:                "Interfaces",
		expectedByDeviceType: byDT,
		expectedByModuleType: byMT,
		actualByDevice:       actual,
		diffSpec: func(expected, actual componentSpec) []string {
			var out []string
			if expected.Type != actual.Type {
				out = append(out, fmt.Sprintf("type: %s -> %s", actual.Type, expected.Type))
			}
			if derefBool(expected.MgmtOnly) != derefBool(actual.MgmtOnly) {
				out = append(out, fmt.Sprintf("mgmt_only: %t -> %t", derefBool(actual.MgmtOnly), derefBool(expected.MgmtOnly)))
			}
			if expected.POEMode != actual.POEMode {
				out = append(out, fmt.Sprintf("poe_mode: %s -> %s", blank(actual.POEMode), blank(expected.POEMode)))
			}
			if expected.POEType != actual.POEType {
				out = append(out, fmt.Sprintf("poe_type: %s -> %s", blank(actual.POEType), blank(expected.POEType)))
			}
			if derefBool(expected.Enabled) != derefBool(actual.Enabled) {
				out = append(out, fmt.Sprintf("enabled: %t -> %t", derefBool(actual.Enabled), derefBool(expected.Enabled)))
			}
			return out
		},
	}
}

func newTypedDriftCheck(label string, templates []typedComponentTemplate, instances []typedComponent) componentDriftCheck {
	byDT := map[int]map[string]componentSpec{}
	byMT := map[int]map[string]componentSpec{}
	for _, t := range templates {
		spec := componentSpec{Type: t.Type.Value}
		if t.DeviceType != nil {
			ensureComponentMap(byDT, t.DeviceType.ID)[t.Name] = spec
		}
		if t.ModuleType != nil {
			ensureComponentMap(byMT, t.ModuleType.ID)[t.Name] = spec
		}
	}
	actual := map[int]map[string]componentSpec{}
	for _, it := range instances {
		ensureComponentMap(actual, it.Device.ID)[it.Name] = componentSpec{Type: it.Type.Value}
	}
	return componentDriftCheck{
		label:                label,
		expectedByDeviceType: byDT,
		expectedByModuleType: byMT,
		actualByDevice:       actual,
		diffSpec: func(expected, actual componentSpec) []string {
			if expected.Type == actual.Type {
				return nil
			}
			return []string{fmt.Sprintf("type: %s -> %s", actual.Type, expected.Type)}
		},
	}
}

func newNamedDriftCheck(label string, templates []namedComponentTemplate, instances []namedComponent) componentDriftCheck {
	byDT := map[int]map[string]componentSpec{}
	byMT := map[int]map[string]componentSpec{}
	for _, t := range templates {
		if t.DeviceType != nil {
			ensureComponentMap(byDT, t.DeviceType.ID)[t.Name] = componentSpec{}
		}
		if t.ModuleType != nil {
			ensureComponentMap(byMT, t.ModuleType.ID)[t.Name] = componentSpec{}
		}
	}
	actual := map[int]map[string]componentSpec{}
	for _, it := range instances {
		ensureComponentMap(actual, it.Device.ID)[it.Name] = componentSpec{}
	}
	return componentDriftCheck{label: label, expectedByDeviceType: byDT, expectedByModuleType: byMT, actualByDevice: actual, diffSpec: func(componentSpec, componentSpec) []string { return nil }}
}

func compareComponentMaps(label string, expected, actual map[string]componentSpec, diff func(expected, actual componentSpec) []string) []string {
	if expected == nil {
		expected = map[string]componentSpec{}
	}
	if actual == nil {
		actual = map[string]componentSpec{}
	}
	var details []string
	missing := diffNames(expected, actual)
	extra := diffNames(actual, expected)
	if len(missing) > 0 {
		details = append(details, fmt.Sprintf("%s missing: %s", label, strings.Join(formatNames(missing), ", ")))
	}
	if len(extra) > 0 {
		details = append(details, fmt.Sprintf("%s extra: %s", label, strings.Join(formatNames(extra), ", ")))
	}
	var mismatches []string
	for name, exp := range expected {
		act, ok := actual[name]
		if !ok {
			continue
		}
		diffs := diff(exp, act)
		if len(diffs) > 0 {
			mismatches = append(mismatches, fmt.Sprintf("%s %s", name, strings.Join(diffs, "; ")))
		}
	}
	sort.Strings(mismatches)
	if len(mismatches) > 0 {
		details = append(details, fmt.Sprintf("%s mismatched: %s", label, strings.Join(mismatches, "; ")))
	}
	return details
}

func (c componentDriftCheck) expectedForDevice(deviceTypeID int, modules []module) map[string]componentSpec {
	out := cloneComponentMap(c.expectedByDeviceType[deviceTypeID])
	for _, mod := range modules {
		for name, spec := range c.expectedByModuleType[mod.ModuleType.ID] {
			expanded := expandModuleTemplateName(name, moduleBayName(mod))
			out[expanded] = spec
		}
	}
	return out
}

func auditWirelessNormalization(s snapshot, cfg auditConfig) checkResult {
	ipsByInterface := ipAssignmentsByInterface(s.IPAddresses)
	ifacesByDevice := interfacesByDevice(s.Interfaces)
	devicesByID := devicesByID(s.Devices)
	var findings []string
	for deviceID, ifaces := range ifacesByDevice {
		dev := devicesByID[deviceID]
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
			if wiredInterfaceComplete(it, ipsByInterface[it.ID]) {
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

func auditPOEPower(s snapshot, cfg auditConfig) checkResult {
	if !cfg.Rules.PoEPower.CheckPoweredDeviceSupply {
		return checkResult{Name: "PoE Power Sufficiency"}
	}
	ifaceByID := map[int]iface{}
	for _, loaded := range s.Interfaces {
		ifaceByID[loaded.ID] = loaded
	}
	var findings []string
	for _, it := range s.Interfaces {
		if choiceValue(it.POEMode) != poeModePD || !it.Enabled || len(it.ConnectedEndpoints) == 0 {
			continue
		}
		requiredType := choiceValue(it.POEType)
		matchedPeer := false
		for _, ep := range it.ConnectedEndpoints {
			peer, ok := ifaceByID[ep.ID]
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

func auditInterfaceVRF(s snapshot, cfg auditConfig) checkResult {
	if !cfg.Rules.InterfaceVRF.RequireOnInterfaces {
		return checkResult{Name: "Interface VRF Coverage"}
	}
	devicesByID := devicesByID(s.Devices)
	ipsByInterface := ipAssignmentsByInterface(s.IPAddresses)
	var findings []string
	for _, it := range s.Interfaces {
		dev := devicesByID[it.Device.ID]
		if dev.Status.Value == deviceStatusPlanned || !it.Enabled {
			continue
		}
		if it.VRF != nil {
			continue
		}
		if isWANInterface(it, dev, devicesByID, cfg) {
			continue
		}
		if !(len(it.ConnectedEndpoints) > 0 || len(ipsByInterface[it.ID]) > 0 || interfaceHasMAC(it) || it.Mode != nil || it.UntaggedVLAN != nil) {
			continue
		}
		findings = append(findings, fmt.Sprintf("%s %s is missing VRF", dev.Name, it.Name))
	}
	sort.Strings(findings)
	return checkResult{Name: "Interface VRF Coverage", Findings: findings}
}

func auditPrivateIPVRF(s snapshot, cfg auditConfig) checkResult {
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

func auditIPVLANConsistency(s snapshot) checkResult {
	ifaceByID := map[int]iface{}
	deviceByID := devicesByID(s.Devices)
	for _, it := range s.Interfaces {
		ifaceByID[it.ID] = it
	}
	prefixes := parsePrefixes(s.Prefixes)
	var findings []string
	for _, ip := range s.IPAddresses {
		if ip.AssignedObjectType != objectTypeInterface {
			continue
		}
		it, ok := ifaceByID[ip.AssignedObjectID]
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
			findings = append(findings, fmt.Sprintf("%s %s carries %s but access VLAN is %s and best prefix VLAN is %s", deviceByID[it.Device.ID].Name, it.Name, ip.Address, it.UntaggedVLAN.Name, match.VLAN.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "IP / VLAN Consistency", Findings: findings}
}

func auditCables(s snapshot) checkResult {
	var findings []string
	for _, c := range s.Cables {
		if c.Type == "" {
			findings = append(findings, fmt.Sprintf("Cable #%d is missing type", c.ID))
		}
		if c.Status.Value == "" {
			findings = append(findings, fmt.Sprintf("Cable #%d is missing status", c.ID))
		}
		if len(c.ATerminations) == 0 || len(c.BTerminations) == 0 {
			findings = append(findings, fmt.Sprintf("Cable #%d is missing a termination on side %s", c.ID, missingCableSide(c)))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Cable Consistency", Findings: findings}
}

func missingCableSide(c cable) string {
	sides := []string{}
	if len(c.ATerminations) == 0 {
		sides = append(sides, "A")
	}
	if len(c.BTerminations) == 0 {
		sides = append(sides, "B")
	}
	return strings.Join(sides, "+")
}

func auditPatchPanelContinuity(s snapshot) checkResult {
	var findings []string
	for _, rp := range s.RearPorts {
		if rp.Cable != nil && len(rp.FrontPorts) == 0 {
			findings = append(findings, fmt.Sprintf("%s rear port %s has a cable but no front-side mapping", rp.Device.Name, rp.Name))
		}
	}
	for _, fp := range s.FrontPorts {
		if fp.Cable != nil && len(fp.RearPorts) == 0 {
			findings = append(findings, fmt.Sprintf("%s front port %s has a cable but no rear-side mapping", fp.Device.Name, fp.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Patch Panel Continuity", Findings: findings}
}

func auditModuleConsistency(s snapshot) checkResult {
	moduleBaysByID := map[int]moduleBay{}
	for _, mb := range s.ModuleBays {
		moduleBaysByID[mb.ID] = mb
	}
	modsByBay := map[int][]module{}
	var findings []string
	for _, mod := range s.Modules {
		if mod.ModuleBay == nil {
			findings = append(findings, fmt.Sprintf("%s module %d has no module bay", mod.Device.Name, mod.ID))
			continue
		}
		mb, ok := moduleBaysByID[mod.ModuleBay.ID]
		if !ok {
			findings = append(findings, fmt.Sprintf("%s module %d references missing module bay %d", mod.Device.Name, mod.ID, mod.ModuleBay.ID))
			continue
		}
		if mb.Device.ID != mod.Device.ID {
			findings = append(findings, fmt.Sprintf("%s module %d is installed in bay %s owned by device %s", mod.Device.Name, mod.ID, mb.Name, mb.Device.Name))
		}
		modsByBay[mod.ModuleBay.ID] = append(modsByBay[mod.ModuleBay.ID], mod)
	}
	for bayID, mods := range modsByBay {
		if len(mods) > 1 {
			ids := []string{}
			for _, mod := range mods {
				ids = append(ids, fmt.Sprintf("%d", mod.ID))
			}
			mb := moduleBaysByID[bayID]
			findings = append(findings, fmt.Sprintf("%s module bay %s has multiple installed modules (%s)", mb.Device.Name, mb.Name, strings.Join(ids, ", ")))
		}
	}
	for _, mb := range s.ModuleBays {
		mods := modsByBay[mb.ID]
		if mb.InstalledModule == nil && len(mods) > 0 {
			findings = append(findings, fmt.Sprintf("%s module bay %s has module list entries but no installed_module pointer", mb.Device.Name, mb.Name))
			continue
		}
		if mb.InstalledModule != nil && len(mods) == 0 {
			findings = append(findings, fmt.Sprintf("%s module bay %s points to installed module %d but no module record references the bay", mb.Device.Name, mb.Name, mb.InstalledModule.ID))
			continue
		}
		if mb.InstalledModule != nil && len(mods) == 1 && mods[0].ID != mb.InstalledModule.ID {
			findings = append(findings, fmt.Sprintf("%s module bay %s installed module pointer is %d but bay contains module %d", mb.Device.Name, mb.Name, mb.InstalledModule.ID, mods[0].ID))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Module Consistency", Findings: findings}
}

func auditMACConsistency(s snapshot) checkResult {
	var findings []string
	byMAC := map[string][]macAddressRecord{}
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

func auditDHCPReservations(s snapshot) checkResult {
	ifaceByID := map[int]iface{}
	for _, it := range s.Interfaces {
		ifaceByID[it.ID] = it
	}
	reservedRanges := taggedRanges(s.IPRanges, tagDHCPReserved)
	poolRanges := taggedRanges(s.IPRanges, tagDHCPPool)
	var findings []string
	findings = append(findings, overlappingRanges(reservedRanges, poolRanges)...)
	for _, ip := range s.IPAddresses {
		if !hasTag(ip.Tags, tagDHCPReserved) {
			continue
		}
		if ip.AssignedObjectType != objectTypeInterface {
			findings = append(findings, fmt.Sprintf("%s is tagged dhcp-reserved but is not assigned to an interface", ip.Address))
			continue
		}
		it, ok := ifaceByID[ip.AssignedObjectID]
		if !ok {
			findings = append(findings, fmt.Sprintf("%s is tagged dhcp-reserved but assigned interface %d was not loaded", ip.Address, ip.AssignedObjectID))
			continue
		}
		if !ipInRanges(ip, reservedRanges) {
			findings = append(findings, fmt.Sprintf("%s is tagged dhcp-reserved but is not inside any dhcp-reserved range", ip.Address))
		}
		_, ok, multi := resolveMAC(it)
		if !ok {
			findings = append(findings, fmt.Sprintf("%s is tagged dhcp-reserved but %s %s has no unambiguous MAC", ip.Address, it.Device.Name, it.Name))
		}
		if multi && it.PrimaryMACAddress == nil && it.MACAddress == "" {
			findings = append(findings, fmt.Sprintf("%s is tagged dhcp-reserved but %s %s has multiple MACs and no primary MAC", ip.Address, it.Device.Name, it.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "DHCP Reservations", Findings: findings}
}

func auditPlannedDevices(s snapshot) checkResult {
	ipsByInterface := ipAssignmentsByInterface(s.IPAddresses)
	ifacesByDevice := interfacesByDevice(s.Interfaces)
	var findings []string
	for _, d := range s.Devices {
		if d.Status.Value != deviceStatusPlanned {
			continue
		}
		for _, it := range ifacesByDevice[d.ID] {
			if len(it.ConnectedEndpoints) > 0 {
				findings = append(findings, fmt.Sprintf("planned device %s has a connected interface %s", d.Name, it.Name))
			}
			if len(ipsByInterface[it.ID]) > 0 {
				findings = append(findings, fmt.Sprintf("planned device %s has IPs assigned to interface %s", d.Name, it.Name))
			}
			if interfaceHasMAC(it) {
				findings = append(findings, fmt.Sprintf("planned device %s has MAC data on interface %s", d.Name, it.Name))
			}
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Planned Device Hygiene", Findings: findings}
}

func auditSwitchLinkSymmetry(s snapshot) checkResult {
	ifaceByID := map[int]iface{}
	deviceByID := devicesByID(s.Devices)
	for _, it := range s.Interfaces {
		ifaceByID[it.ID] = it
	}
	var findings []string
	for _, c := range s.Cables {
		if len(c.ATerminations) != 1 || len(c.BTerminations) != 1 {
			continue
		}
		a := c.ATerminations[0]
		b := c.BTerminations[0]
		if a.ObjectType != objectTypeInterface || b.ObjectType != objectTypeInterface {
			continue
		}
		ia, oka := ifaceByID[a.ObjectID]
		ib, okb := ifaceByID[b.ObjectID]
		if !oka || !okb {
			continue
		}
		da := deviceByID[ia.Device.ID]
		db := deviceByID[ib.Device.ID]
		if da.Role.Name != roleSwitch || db.Role.Name != roleSwitch {
			continue
		}
		if !sameSwitchPortConfig(ia, ib) {
			findings = append(findings, fmt.Sprintf("switch link cable #%d is asymmetric: %s %s vs %s %s", c.ID, da.Name, ia.Name, db.Name, ib.Name))
		}
	}
	sort.Strings(findings)
	return checkResult{Name: "Switch Link Symmetry", Findings: findings}
}
