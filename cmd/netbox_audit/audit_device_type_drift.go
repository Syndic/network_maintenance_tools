package main

import (
	netbox "network_maintainence_tools/internal/netbox"
	"fmt"
	"sort"
	"strings"
)

func auditDeviceTypeDrift(s netbox.Snapshot) checkResult {
	modsByDevice := make(map[int][]netbox.Module)
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

func (c componentDriftCheck) expectedForDevice(deviceTypeID int, modules []netbox.Module) map[string]componentSpec {
	out := cloneComponentMap(c.expectedByDeviceType[deviceTypeID])
	for _, mod := range modules {
		for name, spec := range c.expectedByModuleType[mod.ModuleType.ID] {
			expanded := expandModuleTemplateName(name, moduleBayName(mod))
			out[expanded] = spec
		}
	}
	return out
}

func newInterfaceDriftCheck(templates []netbox.InterfaceTemplate, instances []netbox.Iface) componentDriftCheck {
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

func newTypedDriftCheck(label string, templates []netbox.TypedComponentTemplate, instances []netbox.TypedComponent) componentDriftCheck {
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

func newNamedDriftCheck(label string, templates []netbox.NamedComponentTemplate, instances []netbox.NamedComponent) componentDriftCheck {
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
	return componentDriftCheck{
		label:                label,
		expectedByDeviceType: byDT,
		expectedByModuleType: byMT,
		actualByDevice:       actual,
		diffSpec:             func(componentSpec, componentSpec) []string { return nil },
	}
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
