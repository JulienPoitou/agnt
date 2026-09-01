package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCalculateNextRun(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		interval string
		want     time.Time
	}{
		{"hourly", now.Add(time.Hour)},
		{"daily", now.AddDate(0, 0, 1)},
		{"weekly", now.AddDate(0, 0, 7)},
		{"monthly", now.AddDate(0, 1, 0)},
		{"unknown", now.AddDate(0, 0, 1)}, // fallback to daily
	}

	for _, tc := range cases {
		t.Run(tc.interval, func(t *testing.T) {
			got := calculateNextRun(&ScanSchedule{Interval: tc.interval}, now)
			if !got.Equal(tc.want) {
				t.Errorf("calculateNextRun(%q) = %v, want %v", tc.interval, got, tc.want)
			}
		})
	}
}

func TestCalculateNextRunAnchored(t *testing.T) {
	utc := time.UTC
	// Buenos Aires is UTC-3 year round, so 09:00 local == 12:00 UTC.
	buenosAires, err := time.LoadLocation("America/Argentina/Buenos_Aires")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	cases := []struct {
		name string
		sch  ScanSchedule
		from time.Time
		want time.Time
	}{
		{
			name: "daily later today",
			sch:  ScanSchedule{Interval: "daily", RunAt: "23:30", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 22, 23, 30, 0, 0, utc),
		},
		{
			name: "daily rolls to tomorrow once passed",
			sch:  ScanSchedule{Interval: "daily", RunAt: "09:00", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 23, 9, 0, 0, 0, utc),
		},
		{
			name: "daily exactly at the slot rolls forward",
			sch:  ScanSchedule{Interval: "daily", RunAt: "12:00", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 23, 12, 0, 0, 0, utc),
		},
		{
			name: "hourly uses only the minutes",
			sch:  ScanSchedule{Interval: "hourly", RunAt: "07:15", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 22, 12, 15, 0, 0, utc),
		},
		{
			name: "hourly rolls to the next hour",
			sch:  ScanSchedule{Interval: "hourly", RunAt: "07:15", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 30, 0, 0, utc),
			want: time.Date(2026, 5, 22, 13, 15, 0, 0, utc),
		},
		{
			// 2026-05-22 is a Friday; RunDay 1 = Monday.
			name: "weekly picks the configured weekday",
			sch:  ScanSchedule{Interval: "weekly", RunAt: "03:00", RunDay: 1, Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 25, 3, 0, 0, 0, utc),
		},
		{
			name: "weekly on today rolls a full week when the slot passed",
			sch:  ScanSchedule{Interval: "weekly", RunAt: "03:00", RunDay: int(time.Friday), Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 29, 3, 0, 0, 0, utc),
		},
		{
			name: "weekly sunday is run_day zero",
			sch:  ScanSchedule{Interval: "weekly", RunAt: "03:00", RunDay: int(time.Sunday), Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 24, 3, 0, 0, 0, utc),
		},
		{
			// Persisted schedules are not re-validated on load, so an
			// out-of-range weekday has to wrap instead of hanging the tick.
			name: "weekly wraps an out of range run_day",
			sch:  ScanSchedule{Interval: "weekly", RunAt: "03:00", RunDay: 8, Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 25, 3, 0, 0, 0, utc), // 8 % 7 == Monday
		},
		{
			name: "monthly later this month",
			sch:  ScanSchedule{Interval: "monthly", RunAt: "02:00", RunDay: 28, Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 28, 2, 0, 0, 0, utc),
		},
		{
			name: "monthly rolls to next month once passed",
			sch:  ScanSchedule{Interval: "monthly", RunAt: "02:00", RunDay: 10, Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 6, 10, 2, 0, 0, 0, utc),
		},
		{
			// 2026 is not a leap year: day 31 clamps to February 28.
			name: "monthly clamps to the last day of a short month",
			sch:  ScanSchedule{Interval: "monthly", RunAt: "02:00", RunDay: 31, Timezone: "UTC"},
			from: time.Date(2026, 2, 1, 12, 0, 0, 0, utc),
			want: time.Date(2026, 2, 28, 2, 0, 0, 0, utc),
		},
		{
			name: "timezone is honored",
			sch:  ScanSchedule{Interval: "daily", RunAt: "09:00", Timezone: "America/Argentina/Buenos_Aires"},
			from: time.Date(2026, 5, 22, 6, 0, 0, 0, utc),
			want: time.Date(2026, 5, 22, 9, 0, 0, 0, buenosAires),
		},
		{
			name: "unknown timezone falls back instead of failing",
			sch:  ScanSchedule{Interval: "daily", RunAt: "23:30", Timezone: "Mars/Olympus_Mons"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, time.Local),
			want: time.Date(2026, 5, 22, 23, 30, 0, 0, time.Local),
		},
		{
			name: "malformed run_at falls back to the relative interval",
			sch:  ScanSchedule{Interval: "daily", RunAt: "9am", Timezone: "UTC"},
			from: time.Date(2026, 5, 22, 12, 0, 0, 0, utc),
			want: time.Date(2026, 5, 23, 12, 0, 0, 0, utc),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := calculateNextRun(&tc.sch, tc.from)
			if !got.Equal(tc.want) {
				t.Errorf("calculateNextRun(%+v, %v) = %v, want %v", tc.sch, tc.from, got, tc.want)
			}
			if !got.After(tc.from) {
				t.Errorf("next run %v is not strictly after %v", got, tc.from)
			}
		})
	}
}

func TestNormalizeScheduleTiming(t *testing.T) {
	cases := []struct {
		name       string
		sch        ScanSchedule
		wantErr    bool
		wantRunDay int
	}{
		{name: "empty is valid", sch: ScanSchedule{Interval: "daily"}},
		{name: "valid time", sch: ScanSchedule{Interval: "daily", RunAt: "09:30"}},
		{name: "trims whitespace", sch: ScanSchedule{Interval: "daily", RunAt: "  09:30  "}},
		{name: "rejects 24h", sch: ScanSchedule{Interval: "daily", RunAt: "24:00"}, wantErr: true},
		{name: "rejects bad minutes", sch: ScanSchedule{Interval: "daily", RunAt: "09:60"}, wantErr: true},
		{name: "rejects free text", sch: ScanSchedule{Interval: "daily", RunAt: "9am"}, wantErr: true},
		{name: "rejects unknown timezone", sch: ScanSchedule{Interval: "daily", Timezone: "Mars/Olympus_Mons"}, wantErr: true},
		{name: "accepts known timezone", sch: ScanSchedule{Interval: "daily", Timezone: "America/Argentina/Buenos_Aires"}},
		{name: "weekly sunday", sch: ScanSchedule{Interval: "weekly", RunDay: 0}},
		{name: "weekly rejects out of range", sch: ScanSchedule{Interval: "weekly", RunDay: 7}, wantErr: true},
		{name: "monthly defaults to the first", sch: ScanSchedule{Interval: "monthly", RunDay: 0}, wantRunDay: 1},
		{name: "monthly rejects day 32", sch: ScanSchedule{Interval: "monthly", RunDay: 32}, wantErr: true},
		{name: "daily drops the day component", sch: ScanSchedule{Interval: "daily", RunDay: 4}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := normalizeScheduleTiming(&tc.sch)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (schedule: %+v)", tc.sch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.sch.RunDay != tc.wantRunDay {
				t.Errorf("RunDay = %d, want %d", tc.sch.RunDay, tc.wantRunDay)
			}
			if strings.TrimSpace(tc.sch.RunAt) != tc.sch.RunAt {
				t.Errorf("RunAt was not trimmed: %q", tc.sch.RunAt)
			}
		})
	}
}

func TestSchedulesDiskIO(t *testing.T) {
	s := newTestServer(t, nil)

	sch := &ScanSchedule{
		ID:       "test-sch-1",
		Name:     "Test Daily Scan",
		Interval: "daily",
		Enabled:  true,
		Targets:  []string{"localhost"},
	}

	// Test saving
	err := s.saveScheduleToDisk(sch)
	if err != nil {
		t.Fatalf("saveScheduleToDisk failed: %v", err)
	}

	// Verify file is created
	filePath := filepath.Join(s.dataDir, "_schedules", sch.ID+".json")
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("schedule file not created: %v", err)
	}

	// Test loading
	// First clear memory map
	s.schedulesMu.Lock()
	s.schedules = make(map[string]*ScanSchedule)
	s.schedulesMu.Unlock()

	s.loadSchedulesFromDisk()

	s.schedulesMu.RLock()
	loaded, ok := s.schedules[sch.ID]
	s.schedulesMu.RUnlock()

	if !ok {
		t.Fatalf("schedule not found in memory after loading from disk")
	}
	if loaded.Name != sch.Name || loaded.Interval != sch.Interval {
		t.Errorf("loaded schedule mismatch: %+v", loaded)
	}

	// Test deleting
	err = s.deleteScheduleFromDisk(sch.ID)
	if err != nil {
		t.Fatalf("deleteScheduleFromDisk failed: %v", err)
	}

	// Verify file is gone
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("schedule file still exists after deletion")
	}
}

func TestCheckAndRunSchedules(t *testing.T) {
	s := newTestServer(t, nil)

	// Create an enabled schedule whose NextRun is in the past
	dueSch := &ScanSchedule{
		ID:       "due-1",
		Name:     "Due Daily Scan",
		Interval: "daily",
		Enabled:  true,
		NextRun:  time.Now().Add(-10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	// Create an enabled schedule whose NextRun is in the future
	futureSch := &ScanSchedule{
		ID:       "future-1",
		Name:     "Future Daily Scan",
		Interval: "daily",
		Enabled:  true,
		NextRun:  time.Now().Add(10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	// Create a disabled schedule whose NextRun is in the past
	disabledSch := &ScanSchedule{
		ID:       "disabled-1",
		Name:     "Disabled Daily Scan",
		Interval: "daily",
		Enabled:  false,
		NextRun:  time.Now().Add(-10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	s.schedulesMu.Lock()
	s.schedules[dueSch.ID] = dueSch
	s.schedules[futureSch.ID] = futureSch
	s.schedules[disabledSch.ID] = disabledSch
	s.schedulesMu.Unlock()

	// Clear any historical instances loaded on startup
	s.instancesMu.Lock()
	s.instances = make(map[string]*ScanInstance)
	s.instancesMu.Unlock()

	// Call checkAndRunSchedules
	s.checkAndRunSchedules()

	s.schedulesMu.RLock()
	// Check dueSch: should have run, so LastRun should be updated and NextRun pushed forward
	if dueSch.LastRun.IsZero() {
		t.Errorf("due schedule did not run (LastRun is zero)")
	}
	if !dueSch.NextRun.After(time.Now()) {
		t.Errorf("due schedule NextRun not updated correctly: %v", dueSch.NextRun)
	}

	// Check futureSch: should not have run, LastRun should be zero, NextRun remains unchanged
	if !futureSch.LastRun.IsZero() {
		t.Errorf("future schedule ran unexpectedly")
	}

	// Check disabledSch: should not have run, LastRun should be zero
	if !disabledSch.LastRun.IsZero() {
		t.Errorf("disabled schedule ran unexpectedly")
	}
	s.schedulesMu.RUnlock()

	// Wait briefly to let the goroutine register the scan instance
	time.Sleep(100 * time.Millisecond)

	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()

	// Check that we have exactly one instance registered (from the due schedule)
	if len(s.instances) != 1 {
		t.Errorf("expected 1 registered scan instance, got %d", len(s.instances))
	}
}
