package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	// Embed the IANA timezone database so schedules anchored to a Timezone
	// resolve even on minimal container images that ship without tzdata.
	_ "time/tzdata"

	"github.com/xalgord/xalgorix/v4/internal/safe"
)

type ScanSchedule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Interval string `json:"interval"` // "hourly", "daily", "weekly", "monthly"
	// RunAt anchors the schedule to a wall-clock time of day, "HH:MM" in 24h
	// form. Empty keeps the legacy behavior of firing one interval after the
	// schedule was created or last ran. For "hourly" only the minutes apply.
	RunAt string `json:"run_at,omitempty"`
	// RunDay picks the day within the interval: weekday for "weekly"
	// (0=Sunday … 6=Saturday) and day of month for "monthly" (1-31, clamped to
	// the last day of shorter months). Ignored for the other intervals. No
	// omitempty: 0 is a meaningful weekly value (Sunday).
	RunDay int `json:"run_day"`
	// Timezone is the IANA name RunAt/RunDay are interpreted in, e.g.
	// "America/Argentina/Buenos_Aires". Empty means server local time.
	Timezone       string    `json:"timezone,omitempty"`
	NextRun        time.Time `json:"next_run"`
	LastRun        time.Time `json:"last_run,omitempty"`
	Enabled        bool      `json:"enabled"`
	Targets        []string  `json:"targets"`
	Instruction    string    `json:"instruction,omitempty"`
	ScanMode       string    `json:"scan_mode"`
	SeverityFilter []string  `json:"severity_filter,omitempty"`
	Phases         []int     `json:"phases,omitempty"`
	ReconMode      string    `json:"recon_mode,omitempty"`
	ScanIntensity  string    `json:"scan_intensity,omitempty"`
	CompanyName    string    `json:"company_name,omitempty"`
	LogoPath       string    `json:"logo_path,omitempty"`
	DiscordWebhook string    `json:"discord_webhook,omitempty"`
	Model          string    `json:"model,omitempty"`
}

// runAtPattern validates ScanSchedule.RunAt as a 24h "HH:MM" time of day.
var runAtPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// scheduleTiming is the comparable subset of a schedule that determines when it
// fires. On update, a change here means NextRun has to be recomputed.
type scheduleTiming struct {
	Interval string
	RunAt    string
	RunDay   int
	Timezone string
}

// timing returns the comparable subset of the schedule that decides when it
// fires, so an update can tell whether NextRun has to be recomputed.
func (sch *ScanSchedule) timing() scheduleTiming {
	return scheduleTiming{
		Interval: sch.Interval,
		RunAt:    sch.RunAt,
		RunDay:   sch.RunDay,
		Timezone: sch.Timezone,
	}
}

// normalizeScheduleTiming validates and canonicalizes the day/time-of-day
// fields. It returns an error for values the scheduler could not honor so the
// API answers 400 instead of silently running at the wrong moment.
func normalizeScheduleTiming(sch *ScanSchedule) error {
	if sch == nil {
		return nil
	}
	sch.RunAt = strings.TrimSpace(sch.RunAt)
	sch.Timezone = strings.TrimSpace(sch.Timezone)

	if sch.RunAt != "" && !runAtPattern.MatchString(sch.RunAt) {
		return fmt.Errorf("run_at must be a 24h time of day such as 09:30, got %q", sch.RunAt)
	}
	if sch.Timezone != "" {
		if _, err := time.LoadLocation(sch.Timezone); err != nil {
			return fmt.Errorf("unknown timezone %q", sch.Timezone)
		}
	}

	switch strings.ToLower(sch.Interval) {
	case "weekly":
		if sch.RunDay < 0 || sch.RunDay > 6 {
			return fmt.Errorf("run_day must be 0 (Sunday) through 6 (Saturday) for weekly schedules, got %d", sch.RunDay)
		}
	case "monthly":
		if sch.RunDay == 0 {
			sch.RunDay = 1
		}
		if sch.RunDay < 1 || sch.RunDay > 31 {
			return fmt.Errorf("run_day must be 1 through 31 for monthly schedules, got %d", sch.RunDay)
		}
	default:
		// Hourly and daily have no day component.
		sch.RunDay = 0
	}
	return nil
}

// scheduleLocation resolves the schedule timezone, falling back to server local
// time for empty or unknown names.
func scheduleLocation(name string) *time.Location {
	if name == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		log.Printf("[SCHEDULER] Unknown timezone %q, falling back to server local time", name)
		return time.Local
	}
	return loc
}

// calculateNextRun returns the next execution instant, always strictly after
// from. With RunAt set the schedule is anchored to that wall-clock time (and to
// RunDay for weekly/monthly); otherwise it simply adds one interval to from.
func calculateNextRun(sch *ScanSchedule, from time.Time) time.Time {
	interval := strings.ToLower(sch.Interval)
	parts := runAtPattern.FindStringSubmatch(sch.RunAt)
	if parts == nil {
		return addInterval(interval, from)
	}
	hour, _ := strconv.Atoi(parts[1])
	minute, _ := strconv.Atoi(parts[2])
	loc := scheduleLocation(sch.Timezone)
	base := from.In(loc)

	switch interval {
	case "hourly":
		// Only the minutes matter: the next :MM of any hour.
		next := time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), minute, 0, 0, loc)
		for !next.After(from) {
			next = next.Add(time.Hour)
		}
		return next
	case "weekly":
		// Wrap rather than trust RunDay: schedules loaded from disk are not
		// re-validated, and an out-of-range weekday must not derail the tick.
		weekday := time.Weekday(((sch.RunDay % 7) + 7) % 7)
		next := time.Date(base.Year(), base.Month(), base.Day(), hour, minute, 0, 0, loc)
		next = next.AddDate(0, 0, (int(weekday)-int(next.Weekday())+7)%7)
		if !next.After(from) {
			next = next.AddDate(0, 0, 7)
		}
		return next
	case "monthly":
		// This month first, then the two following ones — enough to clear any
		// slot that already passed.
		for i := 0; i < 3; i++ {
			month := time.Date(base.Year(), base.Month()+time.Month(i), 1, 0, 0, 0, 0, loc)
			next := monthlyRun(month, sch.RunDay, hour, minute, loc)
			if next.After(from) {
				return next
			}
		}
		return from.AddDate(0, 1, 0)
	default:
		// "daily" and any unknown interval.
		next := time.Date(base.Year(), base.Month(), base.Day(), hour, minute, 0, 0, loc)
		if !next.After(from) {
			next = next.AddDate(0, 0, 1)
		}
		return next
	}
}

// addInterval is the unanchored fallback: one interval after from.
func addInterval(interval string, from time.Time) time.Time {
	switch interval {
	case "hourly":
		return from.Add(time.Hour)
	case "daily":
		return from.AddDate(0, 0, 1)
	case "weekly":
		return from.AddDate(0, 0, 7)
	case "monthly":
		return from.AddDate(0, 1, 0)
	default:
		// Default fallback to 1 day
		return from.AddDate(0, 0, 1)
	}
}

// monthlyRun builds the run instant for day within month, clamping to the last
// day when the month is shorter (31 -> 28 in February).
func monthlyRun(month time.Time, day, hour, minute int, loc *time.Location) time.Time {
	if day < 1 {
		day = 1
	}
	// Day 0 of the following month is the last day of this one.
	if last := time.Date(month.Year(), month.Month()+1, 0, 0, 0, 0, 0, loc).Day(); day > last {
		day = last
	}
	return time.Date(month.Year(), month.Month(), day, hour, minute, 0, 0, loc)
}

// loadSchedulesFromDisk reads schedules directory and loads them into memory.
func (s *Server) loadSchedulesFromDisk() {
	dir := filepath.Join(s.dataDir, "_schedules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("[SCHEDULER] Error creating schedules dir: %v", err)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[SCHEDULER] Error reading schedules dir: %v", err)
		return
	}
	s.schedulesMu.Lock()
	defer s.schedulesMu.Unlock()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[SCHEDULER] Error reading schedule file %s: %v", path, err)
			continue
		}
		var sch ScanSchedule
		if err := json.Unmarshal(data, &sch); err != nil {
			log.Printf("[SCHEDULER] Error decoding schedule %s: %v", path, err)
			continue
		}
		normalizeScheduleActivity(&sch)
		if err := normalizeScheduleTiming(&sch); err != nil {
			// Keep the schedule: calculateNextRun tolerates the bad value, so
			// losing the whole entry over it would be worse.
			log.Printf("[SCHEDULER] Schedule %s has invalid timing (%v), scheduling defensively", sch.ID, err)
		}
		s.schedules[sch.ID] = &sch
	}
	log.Printf("[SCHEDULER] Loaded %d schedules from disk", len(s.schedules))
}

// saveScheduleToDisk writes a schedule to disk.
func (s *Server) saveScheduleToDisk(sch *ScanSchedule) error {
	dir := filepath.Join(s.dataDir, "_schedules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(sch, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(dir, sch.ID+".json")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath) // best-effort cleanup
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// deleteScheduleFromDisk deletes a schedule file.
func (s *Server) deleteScheduleFromDisk(id string) error {
	path := filepath.Join(s.dataDir, "_schedules", id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// startScheduler runs the background checker loop.
func (s *Server) startScheduler() {
	// Evaluate overdue schedules immediately on startup so scans missed
	// while the server was down don't wait a full ticker interval.
	s.checkAndRunSchedules()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	log.Printf("[SCHEDULER] Started background scheduler ticker")
	for {
		select {
		case <-s.shutdownChan:
			log.Printf("[SCHEDULER] Stopping background scheduler")
			return
		case <-ticker.C:
			s.checkAndRunSchedules()
		}
	}
}

// checkAndRunSchedules evaluates all schedules and launches due scans.
func (s *Server) checkAndRunSchedules() {
	defer safe.Recover("scheduler.tick", "")
	s.schedulesMu.Lock()
	defer s.schedulesMu.Unlock()

	now := time.Now()
	for _, sch := range s.schedules {
		func(sch *ScanSchedule) {
			defer safe.Recover("scheduler."+sch.ID, "")
			if !sch.Enabled {
				return
			}
			if now.After(sch.NextRun) || now.Equal(sch.NextRun) {
				log.Printf("[SCHEDULER] Triggering scheduled scan: %s (Targets: %v)", sch.Name, sch.Targets)

				req := ScanRequest{
					Targets:        sch.Targets,
					Instruction:    sch.Instruction,
					ScanMode:       sch.ScanMode,
					SeverityFilter: sch.SeverityFilter,
					Phases:         sch.Phases,
					ReconMode:      sch.ReconMode,
					ScanIntensity:  sch.ScanIntensity,
					CompanyName:    sch.CompanyName,
					LogoPath:       sch.LogoPath,
					DiscordWebhook: sch.DiscordWebhook,
					Name:           sch.Name + " (Scheduled)",
					Model:          sch.Model,
				}

				scanCfg := *s.cfg
				if sch.Model != "" {
					scanCfg.LLM = sch.Model
				}
				instanceID := randomSlug()

				go s.runMultiScan(req, &scanCfg, instanceID)

				sch.LastRun = now
				sch.NextRun = calculateNextRun(sch, now)

				if err := s.saveScheduleToDisk(sch); err != nil {
					log.Printf("[SCHEDULER] Error saving triggered schedule %s: %v", sch.ID, err)
				}
			}
		}(sch)
	}
}
