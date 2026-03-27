package main

import (
	"net/netip"
	"time"

	netbox "network_maintainence_tools/internal/netbox"
)

type parsedPrefix struct {
	Prefix netip.Prefix
	VLAN   *netbox.VLANRef
	VRFID  int
}

type componentSpec struct {
	Type     string
	MgmtOnly *bool
	POEMode  string
	POEType  string
	Enabled  *bool
}

type driftRecord struct {
	Device  string   `json:"device"`
	Model   string   `json:"model"`
	Details []string `json:"details"`
}

type componentDriftCheck struct {
	label                string
	expectedByDeviceType map[int]map[string]componentSpec
	expectedByModuleType map[int]map[string]componentSpec
	actualByDevice       map[int]map[string]componentSpec
	diffSpec             func(expected, actual componentSpec) []string
}

type snapshotMeta struct {
	Attempts int                 `json:"attempts"`
	Change   netbox.ObjectChange `json:"latest_change"`
}

type checkResult struct {
	Name     string        `json:"name"`
	Findings []string      `json:"findings"`
	Extra    []driftRecord `json:"extra,omitempty"`
}

type checkTiming struct {
	ID       string
	Name     string
	Duration time.Duration
	Findings int
}

type reportTiming struct {
	Total    time.Duration
	Snapshot netbox.SnapshotLoadStats
	Checks   []checkTiming
}

type report struct {
	Snapshot snapshotMeta  `json:"snapshot"`
	Checks   []checkResult `json:"checks"`
	Timing   reportTiming  `json:"-"`
}
