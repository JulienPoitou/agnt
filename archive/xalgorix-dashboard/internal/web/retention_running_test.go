package web

import "testing"

// TestRunningInstanceIDsOnlyActive guards the retention no-op regression: only
// instances whose Status is active ("running"/"paused") count as running. A
// completed/stopped/saved instance still living in s.instances must NOT be
// treated as running, otherwise pruneExpiredScans skips it forever and the
// configured retention window never deletes anything.
func TestRunningInstanceIDsOnlyActive(t *testing.T) {
	s := &Server{instances: map[string]*ScanInstance{
		"run":    {Status: "running"},
		"pause":  {Status: "paused"},
		"RUN":    {Status: "Running"}, // case-insensitive per instanceIsActive
		"done":   {Status: "finished"},
		"stop":   {Status: "stopped"},
		"saved":  {Status: "saved"},
		"empty":  {Status: ""},
		"nilent": nil,
	}}

	got := s.runningInstanceIDs()

	wantActive := []string{"run", "pause", "RUN"}
	for _, id := range wantActive {
		if !got[id] {
			t.Errorf("instance %q should be treated as running", id)
		}
	}
	for _, id := range []string{"done", "stop", "saved", "empty", "nilent"} {
		if got[id] {
			t.Errorf("inactive instance %q must NOT be treated as running (retention no-op bug)", id)
		}
	}
	if len(got) != len(wantActive) {
		t.Errorf("runningInstanceIDs() = %v; want exactly %v", got, wantActive)
	}
}
