package main

import (
	"time"

	audit "network_maintainence_tools/internal/audit"
	netbox "network_maintainence_tools/internal/netbox"
)

type snapshotMeta struct {
	Attempts int                 `json:"attempts"`
	Change   netbox.ObjectChange `json:"latest_change"`
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
	Snapshot snapshotMeta        `json:"snapshot"`
	Checks   []audit.CheckResult `json:"checks"`
	Timing   reportTiming        `json:"-"`
}
