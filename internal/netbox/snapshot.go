package netbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ObjectTypeInterface is the NetBox content-type string for dcim.interface.
const ObjectTypeInterface = "dcim.interface"

// LoadObserver receives progress notifications during snapshot loading.
type LoadObserver interface {
	SnapshotAttemptStart(attempt, maxAttempts, taskCount int)
	SnapshotTaskStart(name string)
	SnapshotTaskComplete(completed, total int, stats FetchTiming, totalRequests int)
	SnapshotAttemptRetry(attempt, maxAttempts int, delay time.Duration, before, after ObjectChange)
}

// LoadConsistentSnapshot fetches a consistent snapshot from NetBox, retrying
// up to maxAttempts times if the data changes during the fetch.
func LoadConsistentSnapshot(ctx context.Context, client *Client, maxAttempts int, retryDelay time.Duration, obs LoadObserver) (Snapshot, error) {
	var lastErr error
	var totalStart = time.Now()
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		startChange, err := client.LatestChange(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		if obs != nil {
			obs.SnapshotAttemptStart(attempt, maxAttempts, SnapshotTaskCount())
		}
		snap, err := loadSnapshot(ctx, client, obs)
		if err != nil {
			lastErr = err
			continue
		}
		endChange, err := client.LatestChange(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		if startChange.ID == endChange.ID && startChange.Time == endChange.Time {
			snap.LatestChange = endChange
			snap.SnapshotAttempts = attempt
			snap.LoadStats.Duration = time.Since(totalStart)
			return snap, nil
		}
		lastErr = fmt.Errorf("snapshot changed during load (%d -> %d)", startChange.ID, endChange.ID)
		if obs != nil {
			obs.SnapshotAttemptRetry(attempt, maxAttempts, retryDelay, startChange, endChange)
		}
		if attempt < maxAttempts {
			time.Sleep(retryDelay)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("unable to capture coherent snapshot")
	}
	return Snapshot{}, lastErr
}

// SnapshotTaskCount returns the number of parallel fetch tasks in a snapshot load.
func SnapshotTaskCount() int {
	return len(snapshotTasks())
}

type snapshotTask struct {
	name string
	run  func(context.Context, *Client, *Snapshot) (FetchTiming, error)
}

func snapshotTasks() []snapshotTask {
	return []snapshotTask{
		{"devices", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[Device](ctx, c, "/api/dcim/devices/")
			s.Devices = data
			return stats, err
		}},
		{"interfaces", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[Iface](ctx, c, "/api/dcim/interfaces/")
			s.Interfaces = data
			return stats, err
		}},
		{"interface-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[InterfaceTemplate](ctx, c, "/api/dcim/interface-templates/")
			s.InterfaceTemplates = data
			return stats, err
		}},
		{"console-ports", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponent](ctx, c, "/api/dcim/console-ports/")
			s.ConsolePorts = data
			return stats, err
		}},
		{"console-port-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponentTemplate](ctx, c, "/api/dcim/console-port-templates/")
			s.ConsolePortTemplates = data
			return stats, err
		}},
		{"console-server-ports", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponent](ctx, c, "/api/dcim/console-server-ports/")
			s.ConsoleServerPorts = data
			return stats, err
		}},
		{"console-server-port-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponentTemplate](ctx, c, "/api/dcim/console-server-port-templates/")
			s.ConsoleServerPortTemplates = data
			return stats, err
		}},
		{"power-ports", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponent](ctx, c, "/api/dcim/power-ports/")
			s.PowerPorts = data
			return stats, err
		}},
		{"power-port-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponentTemplate](ctx, c, "/api/dcim/power-port-templates/")
			s.PowerPortTemplates = data
			return stats, err
		}},
		{"power-outlets", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponent](ctx, c, "/api/dcim/power-outlets/")
			s.PowerOutlets = data
			return stats, err
		}},
		{"power-outlet-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[TypedComponentTemplate](ctx, c, "/api/dcim/power-outlet-templates/")
			s.PowerOutletTemplates = data
			return stats, err
		}},
		{"front-ports", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[FrontPort](ctx, c, "/api/dcim/front-ports/")
			s.FrontPorts = data
			return stats, err
		}},
		{"front-port-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[FrontPortTemplate](ctx, c, "/api/dcim/front-port-templates/")
			s.FrontPortTemplates = data
			return stats, err
		}},
		{"rear-ports", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[RearPort](ctx, c, "/api/dcim/rear-ports/")
			s.RearPorts = data
			return stats, err
		}},
		{"rear-port-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[RearPortTemplate](ctx, c, "/api/dcim/rear-port-templates/")
			s.RearPortTemplates = data
			return stats, err
		}},
		{"device-bays", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[NamedComponent](ctx, c, "/api/dcim/device-bays/")
			s.DeviceBays = data
			return stats, err
		}},
		{"device-bay-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[NamedComponentTemplate](ctx, c, "/api/dcim/device-bay-templates/")
			s.DeviceBayTemplates = data
			return stats, err
		}},
		{"module-bays", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[ModuleBay](ctx, c, "/api/dcim/module-bays/")
			s.ModuleBays = data
			return stats, err
		}},
		{"module-bay-templates", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[NamedComponentTemplate](ctx, c, "/api/dcim/module-bay-templates/")
			s.ModuleBayTemplates = data
			return stats, err
		}},
		{"modules", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[Module](ctx, c, "/api/dcim/modules/")
			s.Modules = data
			return stats, err
		}},
		{"ip-addresses", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[IPAddress](ctx, c, "/api/ipam/ip-addresses/")
			s.IPAddresses = data
			return stats, err
		}},
		{"ip-ranges", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[IPRange](ctx, c, "/api/ipam/ip-ranges/")
			s.IPRanges = data
			return stats, err
		}},
		{"prefixes", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[Prefix](ctx, c, "/api/ipam/prefixes/")
			s.Prefixes = data
			return stats, err
		}},
		{"cables", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[Cable](ctx, c, "/api/dcim/cables/")
			s.Cables = data
			return stats, err
		}},
		{"mac-addresses", func(ctx context.Context, c *Client, s *Snapshot) (FetchTiming, error) {
			data, stats, err := fetchAll[MACAddressRecord](ctx, c, "/api/dcim/mac-addresses/")
			s.MACAddresses = data
			return stats, err
		}},
	}
}

func loadSnapshot(ctx context.Context, c *Client, obs LoadObserver) (Snapshot, error) {
	var snap Snapshot
	tasks := snapshotTasks()
	type taskResult struct {
		name  string
		stats FetchTiming
		err   error
	}
	results := make(chan taskResult, len(tasks))
	var wg sync.WaitGroup
	for _, task := range tasks {
		task := task
		if obs != nil {
			obs.SnapshotTaskStart(task.name)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats, err := task.run(ctx, c, &snap)
			stats.Name = task.name
			results <- taskResult{name: task.name, stats: stats, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	completedTasks := 0
	totalRequests := 0
	var fetches []FetchTiming
	var errs []string
	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", result.name, result.err))
			continue
		}
		completedTasks++
		totalRequests += result.stats.Requests
		fetches = append(fetches, result.stats)
		if obs != nil {
			obs.SnapshotTaskComplete(completedTasks, len(tasks), result.stats, totalRequests)
		}
	}
	if len(errs) > 0 {
		return Snapshot{}, errors.New(strings.Join(errs, "; "))
	}
	snap.LoadStats.RequestCount = totalRequests
	snap.LoadStats.Fetches = fetches
	snap.buildIndexes()
	return snap, nil
}

// buildIndexes pre-computes lookup maps that are used by multiple audit
// checks. Building them here — once, after all data is fetched — means the
// parallel checks can share read-only maps instead of each independently
// iterating the same slices.
func (s *Snapshot) buildIndexes() {
	s.DevicesByID = make(map[int]Device, len(s.Devices))
	for _, d := range s.Devices {
		s.DevicesByID[d.ID] = d
	}

	s.InterfacesByID = make(map[int]Iface, len(s.Interfaces))
	s.InterfacesByDevice = make(map[int][]Iface)
	for _, it := range s.Interfaces {
		s.InterfacesByID[it.ID] = it
		s.InterfacesByDevice[it.Device.ID] = append(s.InterfacesByDevice[it.Device.ID], it)
	}

	s.IPsByInterface = make(map[int][]IPAddress)
	for _, ip := range s.IPAddresses {
		if ip.AssignedObjectType == ObjectTypeInterface {
			s.IPsByInterface[ip.AssignedObjectID] = append(s.IPsByInterface[ip.AssignedObjectID], ip)
		}
	}

	s.ModuleBaysByID = make(map[int]ModuleBay, len(s.ModuleBays))
	for _, mb := range s.ModuleBays {
		s.ModuleBaysByID[mb.ID] = mb
	}
}

func fetchAll[T any](ctx context.Context, client *Client, path string) ([]T, FetchTiming, error) {
	started := time.Now()
	out, requests, pages, err := FetchAll[T](ctx, client, path)
	if err != nil {
		return nil, FetchTiming{}, err
	}
	return out, FetchTiming{Requests: requests, Pages: pages, Items: len(out), Duration: time.Since(started)}, nil
}
