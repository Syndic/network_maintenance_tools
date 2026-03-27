package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	netbox "network_maintainence_tools/internal/netbox"
	"network_maintainence_tools/internal/shared"
)

type colorizer struct {
	enabled bool
}

var stderrColors colorizer

func totalFindings(rep report) int {
	total := 0
	for _, check := range rep.Checks {
		total += len(check.Findings)
		for _, drift := range check.Extra {
			total += len(drift.Details)
		}
	}
	return total
}

func newColorizer(mode string, file *os.File) (colorizer, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", shared.ColorAuto:
		return colorizer{enabled: shouldColor(file)}, nil
	case shared.ColorAlways:
		return colorizer{enabled: true}, nil
	case shared.ColorNever:
		return colorizer{enabled: false}, nil
	default:
		return colorizer{}, fmt.Errorf("expected %s, %s, or %s", shared.ColorAuto, shared.ColorAlways, shared.ColorNever)
	}
}

func shouldColor(file *os.File) bool {
	if os.Getenv(shared.EnvNoColor) != "" {
		return false
	}
	if term := os.Getenv("TERM"); term == "" || term == shared.TermDumb {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func (c colorizer) wrap(code, text string) string {
	if !c.enabled {
		return text
	}
	return code + text + "\033[0m"
}

func (c colorizer) pass(text string) string {
	return c.wrap("\033[32m", text)
}

func (c colorizer) warn(text string) string {
	return c.wrap("\033[38;5;214m", text)
}

func (c colorizer) fail(text string) string {
	return c.wrap("\033[31m", text)
}

func printTextReport(rep report, colors colorizer) {
	checksWithFindings := 0
	for _, check := range rep.Checks {
		if len(check.Findings) > 0 || len(check.Extra) > 0 {
			checksWithFindings++
		}
	}

	fmt.Printf("Snapshot: %d attempt(s), latest change #%d at %s\n", rep.Snapshot.Attempts, rep.Snapshot.Change.ID, rep.Snapshot.Change.Time)
	fmt.Printf("Checks: %d\n", len(rep.Checks))
	fmt.Printf("Checks with findings: %d\n", checksWithFindings)
	fmt.Printf("Total findings: %d\n", totalFindings(rep))
	fmt.Printf("Timing: total=%s, snapshot=%s (%d requests)\n", formatDuration(rep.Timing.Total), formatDuration(rep.Timing.Snapshot.Duration), rep.Timing.Snapshot.RequestCount)

	if len(rep.Timing.Snapshot.Fetches) > 0 {
		fmt.Printf("Snapshot collections by duration:\n")
		for _, fetch := range sortTimingDescending(rep.Timing.Snapshot.Fetches, func(f netbox.FetchTiming) time.Duration { return f.Duration }) {
			fmt.Printf("- %s: %s, %d requests, %d items\n", fetch.Name, formatDuration(fetch.Duration), fetch.Requests, fetch.Items)
		}
	}
	if len(rep.Timing.Checks) > 0 {
		fmt.Printf("Check durations:\n")
		for _, timing := range sortTimingDescending(rep.Timing.Checks, func(t checkTiming) time.Duration { return t.Duration }) {
			fmt.Printf("- %s: %s, %d findings\n", timing.Name, formatDuration(timing.Duration), timing.Findings)
		}
	}

	for _, check := range rep.Checks {
		status := shared.StatusPass
		if len(check.Findings) > 0 || len(check.Extra) > 0 {
			status = shared.StatusWarn
		}
		coloredStatus := colors.pass(status)
		if status == shared.StatusWarn {
			coloredStatus = colors.warn(status)
		}
		count := len(check.Findings)
		for _, drift := range check.Extra {
			count += len(drift.Details)
		}
		fmt.Printf("\n[%s] %s (%d)\n", coloredStatus, check.Name, count)
		for _, finding := range check.Findings {
			fmt.Printf("- %s\n", finding)
		}
		for _, drift := range check.Extra {
			fmt.Printf("- %s (%s)\n", drift.Device, drift.Model)
			for _, detail := range drift.Details {
				fmt.Printf("  %s\n", detail)
			}
		}
	}
}

func fatalf(format string, args ...any) {
	if stderrColors.enabled {
		fmt.Fprintf(os.Stderr, "%s %s\n", stderrColors.fail(shared.StatusFail), fmt.Sprintf(format, args...))
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n", shared.StatusFail, fmt.Sprintf(format, args...))
	}
	os.Exit(1)
}
