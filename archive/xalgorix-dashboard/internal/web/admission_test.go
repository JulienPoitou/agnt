package web

import (
	"testing"
	"time"
)

func TestAdmissionMemoryUnreflected(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		startedAt string
		want      bool
	}{
		{name: "new admission", startedAt: now.Add(-5 * time.Second).Format(time.RFC3339Nano), want: true},
		{name: "window boundary", startedAt: now.Add(-admissionMemoryReflectionWindow).Format(time.RFC3339Nano), want: false},
		{name: "settled admission", startedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), want: false},
		{name: "future timestamp", startedAt: now.Add(time.Minute).Format(time.RFC3339Nano), want: false},
		{name: "invalid timestamp", startedAt: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := admissionMemoryUnreflected(tt.startedAt, now); got != tt.want {
				t.Fatalf("admissionMemoryUnreflected(%q) = %v, want %v", tt.startedAt, got, tt.want)
			}
		})
	}
}
