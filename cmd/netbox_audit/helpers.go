package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

func poeSupplySufficient(supplyType, requiredType string, cfg auditConfig) (bool, string) {
	if requiredType == "" {
		if cfg.Rules.PoEPower.UnknownTypePolicy == poeUnknownTypeIgnore {
			return true, ""
		}
		return false, "PD interface is missing poe_type"
	}
	if supplyType == "" {
		if cfg.Rules.PoEPower.UnknownTypePolicy == poeUnknownTypeIgnore {
			return true, ""
		}
		return false, "PSE interface is missing poe_type"
	}
	if supplyType == requiredType {
		return true, ""
	}
	if sr, ok := poeTypeRank(supplyType); ok {
		if rr, ok := poeTypeRank(requiredType); ok {
			if sr >= rr {
				return true, ""
			}
			return false, "PSE PoE type is weaker than PD requirement"
		}
	}
	if cfg.Rules.PoEPower.UnknownTypePolicy == poeUnknownTypeIgnore {
		return true, ""
	}
	return false, "PoE types are not directly comparable"
}

func poeTypeRank(v string) (int, bool) {
	switch v {
	case poeTypeAF:
		return 1, true
	case poeTypeAT:
		return 2, true
	case poeTypeBT3:
		return 3, true
	case poeTypeBT4:
		return 4, true
	default:
		return 0, false
	}
}

func sameSwitchPortConfig(a, b iface) bool {
	if choiceValue(a.Mode) != choiceValue(b.Mode) {
		return false
	}
	if vlanID(a.UntaggedVLAN) != vlanID(b.UntaggedVLAN) {
		return false
	}
	at := taggedVLANIDs(a.TaggedVLANs)
	bt := taggedVLANIDs(b.TaggedVLANs)
	if len(at) != len(bt) {
		return false
	}
	for i := range at {
		if at[i] != bt[i] {
			return false
		}
	}
	return true
}


func parsePrefixes(prefixes []prefix) []parsedPrefix {
	out := make([]parsedPrefix, 0, len(prefixes))
	for _, p := range prefixes {
		net, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			continue
		}
		out = append(out, parsedPrefix{Prefix: net, VLAN: p.VLAN, VRFID: vrfID(p.VRF)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.Bits() > out[j].Prefix.Bits() })
	return out
}

func bestPrefixMatch(prefixes []parsedPrefix, addr netip.Addr, vrf int) *parsedPrefix {
	for _, p := range prefixes {
		if p.VRFID != vrf {
			continue
		}
		if p.Prefix.Contains(addr) {
			p := p
			return &p
		}
	}
	return nil
}

func taggedRanges(ranges []ipRange, slug string) []ipRange {
	var out []ipRange
	for _, r := range ranges {
		if hasTag(r.Tags, slug) {
			out = append(out, r)
		}
	}
	return out
}

func overlappingRanges(a, b []ipRange) []string {
	var findings []string
	for _, ra := range a {
		astart, aok := parseAddr(ra.StartAddress)
		aend, aendOK := parseAddr(ra.EndAddress)
		if !aok || !aendOK {
			continue
		}
		for _, rb := range b {
			if vrfID(ra.VRF) != vrfID(rb.VRF) {
				continue
			}
			bstart, bok := parseAddr(rb.StartAddress)
			bend, bendOK := parseAddr(rb.EndAddress)
			if !bok || !bendOK || astart.BitLen() != bstart.BitLen() {
				continue
			}
			if rangesOverlap(astart, aend, bstart, bend) {
				findings = append(findings, fmt.Sprintf("Range overlap between %s-%s and %s-%s", ra.StartAddress, ra.EndAddress, rb.StartAddress, rb.EndAddress))
			}
		}
	}
	sort.Strings(findings)
	return findings
}

func rangesOverlap(aStart, aEnd, bStart, bEnd netip.Addr) bool {
	return aStart.Compare(bEnd) <= 0 && bStart.Compare(aEnd) <= 0
}

func ipInRanges(ip ipAddress, ranges []ipRange) bool {
	addr, ok := bareAddr(ip.Address)
	if !ok {
		return false
	}
	for _, r := range ranges {
		if vrfID(ip.VRF) != vrfID(r.VRF) {
			continue
		}
		start, ok1 := parseAddr(r.StartAddress)
		end, ok2 := parseAddr(r.EndAddress)
		if !ok1 || !ok2 || start.BitLen() != addr.BitLen() {
			continue
		}
		if start.Compare(addr) <= 0 && addr.Compare(end) <= 0 {
			return true
		}
	}
	return false
}

func resolveMAC(it iface) (mac string, ok bool, multi bool) {
	if it.PrimaryMACAddress != nil && it.PrimaryMACAddress.MACAddress != "" {
		return it.PrimaryMACAddress.MACAddress, true, len(it.MACAddresses) > 1
	}
	if it.MACAddress != "" {
		return it.MACAddress, true, len(it.MACAddresses) > 1
	}
	if len(it.MACAddresses) == 1 && it.MACAddresses[0].MACAddress != "" {
		return it.MACAddresses[0].MACAddress, true, false
	}
	if len(it.MACAddresses) > 1 {
		return "", false, true
	}
	return "", false, false
}

func interfaceHasMAC(it iface) bool {
	_, ok, _ := resolveMAC(it)
	return ok
}

func wiredInterfaceComplete(it iface, ips []ipAddress) bool {
	return len(it.ConnectedEndpoints) > 0 && (it.VRF != nil || it.Mode != nil || it.UntaggedVLAN != nil || len(ips) > 0 || interfaceHasMAC(it))
}

func isWirelessType(t string) bool {
	return strings.HasPrefix(t, wirelessTypePrefix)
}

func isWANInterface(it iface, dev device, devices map[int]device, cfg auditConfig) bool {
	if cfg.isWANRole(dev.Role.Name) {
		return true
	}
	for _, ep := range it.ConnectedEndpoints {
		if ep.Device == nil {
			continue
		}
		peer, ok := devices[ep.Device.ID]
		if ok && cfg.isWANRole(peer.Role.Name) {
			return true
		}
	}
	return false
}

func boolPtr(v bool) *bool { return &v }

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

func choiceValue(v *choice) string {
	if v == nil {
		return ""
	}
	return v.Value
}

func blank(v string) string {
	if v == "" {
		return "<blank>"
	}
	return v
}

func bareAddr(cidr string) (netip.Addr, bool) {
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		return prefix.Addr(), true
	}
	if addr, err := netip.ParseAddr(cidr); err == nil {
		return addr, true
	}
	return netip.Addr{}, false
}

func parseAddr(value string) (netip.Addr, bool) {
	return bareAddr(value)
}

func vrfID(vrf *vrfRef) int {
	if vrf == nil {
		return 0
	}
	return vrf.ID
}

func hasTag(tags []tagRef, slug string) bool {
	for _, tag := range tags {
		if tag.Slug == slug {
			return true
		}
	}
	return false
}

func normalizeMAC(v string) string {
	return strings.ToUpper(strings.TrimSpace(v))
}

func describeAssignedObject(obj *assignedObjectRef) string {
	if obj == nil {
		return "<unassigned>"
	}
	if obj.Device != nil {
		return fmt.Sprintf("%s %s", obj.Device.Name, obj.Name)
	}
	return obj.Name
}

func ensureComponentMap(m map[int]map[string]componentSpec, id int) map[string]componentSpec {
	if _, ok := m[id]; !ok {
		m[id] = map[string]componentSpec{}
	}
	return m[id]
}

func cloneComponentMap(src map[string]componentSpec) map[string]componentSpec {
	out := map[string]componentSpec{}
	for name, spec := range src {
		out[name] = spec
	}
	return out
}

func diffNames(a, b map[string]componentSpec) []string {
	var names []string
	for name := range a {
		if _, ok := b[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func formatNames(names []string) []string {
	portRanges, others := groupPortNames(names)
	out := formatPortRanges(portRanges)
	out = append(out, others...)
	return out
}

func groupPortNames(names []string) ([][2]int, []string) {
	var nums []int
	var others []string
	for _, name := range names {
		if n, ok := parsePortNumber(name); ok {
			nums = append(nums, n)
		} else {
			others = append(others, name)
		}
	}
	sort.Ints(nums)
	sort.Strings(others)
	var ranges [][2]int
	if len(nums) > 0 {
		start, prev := nums[0], nums[0]
		for _, n := range nums[1:] {
			if n == prev+1 {
				prev = n
				continue
			}
			ranges = append(ranges, [2]int{start, prev})
			start, prev = n, n
		}
		ranges = append(ranges, [2]int{start, prev})
	}
	return ranges, others
}

func formatPortRanges(ranges [][2]int) []string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r[0] == r[1] {
			out = append(out, fmt.Sprintf("Port %d", r[0]))
		} else {
			out = append(out, fmt.Sprintf("Ports %d-%d", r[0], r[1]))
		}
	}
	return out
}

var portPattern = regexp.MustCompile(`^Port (\d+)$`)
var trailingTokenPattern = regexp.MustCompile(`([A-Za-z0-9/_-]+)$`)

func parsePortNumber(name string) (int, bool) {
	m := portPattern.FindStringSubmatch(name)
	if len(m) != 2 {
		return 0, false
	}
	var n int
	_, err := fmt.Sscanf(m[1], "%d", &n)
	return n, err == nil
}

func moduleBayName(mod module) string {
	if mod.ModuleBay == nil {
		return "module"
	}
	return mod.ModuleBay.Name
}

func expandModuleTemplateName(templateName, bayName string) string {
	if !strings.Contains(templateName, "{module}") {
		return templateName
	}
	token := bayName
	if match := trailingTokenPattern.FindStringSubmatch(bayName); len(match) == 2 {
		token = match[1]
	}
	return strings.ReplaceAll(templateName, "{module}", token)
}

func frontTemplatesToTyped(in []frontPortTemplate) []typedComponentTemplate {
	out := make([]typedComponentTemplate, 0, len(in))
	for _, fp := range in {
		out = append(out, typedComponentTemplate{ID: fp.ID, DeviceType: fp.DeviceType, ModuleType: fp.ModuleType, Name: fp.Name, Type: fp.Type})
	}
	return out
}

func rearTemplatesToTyped(in []rearPortTemplate) []typedComponentTemplate {
	out := make([]typedComponentTemplate, 0, len(in))
	for _, rp := range in {
		out = append(out, typedComponentTemplate{ID: rp.ID, DeviceType: rp.DeviceType, ModuleType: rp.ModuleType, Name: rp.Name, Type: rp.Type})
	}
	return out
}

func frontPortsToTyped(in []frontPort) []typedComponent {
	out := make([]typedComponent, 0, len(in))
	for _, fp := range in {
		out = append(out, typedComponent{ID: fp.ID, Name: fp.Name, Device: fp.Device, Module: fp.Module, Type: fp.Type})
	}
	return out
}

func rearPortsToTyped(in []rearPort) []typedComponent {
	out := make([]typedComponent, 0, len(in))
	for _, rp := range in {
		out = append(out, typedComponent{ID: rp.ID, Name: rp.Name, Device: rp.Device, Module: rp.Module, Type: rp.Type})
	}
	return out
}

func moduleBaysToNamed(in []moduleBay) []namedComponent {
	out := make([]namedComponent, 0, len(in))
	for _, mb := range in {
		out = append(out, namedComponent{ID: mb.ID, Name: mb.Name, Device: mb.Device, Module: mb.Module})
	}
	return out
}

func vlanID(v *vlanRef) int {
	if v == nil {
		return 0
	}
	return v.ID
}

func taggedVLANIDs(vlans []vlanRef) []int {
	out := make([]int, 0, len(vlans))
	for _, vlan := range vlans {
		out = append(out, vlan.ID)
	}
	sort.Ints(out)
	return out
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}
