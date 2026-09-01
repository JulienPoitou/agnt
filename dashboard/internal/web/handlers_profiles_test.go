package web

import "testing"

// TestProfileKeyFromPath locks in the parsing contract of the
// profileKeyFromPath helper. The helper must return "" for any
// shape that doesn't have a single, slash-free key segment between
// the "/api/auth/profiles/" prefix and the optional suffix; that
// strictness is what guards the profile handlers against
// path-traversal style mismatches and silent multi-segment
// matching.
//
// Note on URL-encoded slashes: Go's net/http ServeMux percent-decodes
// the path before dispatching, so a request to
// "/api/auth/profiles/foo%2Fbar" arrives at the helper as
// "/api/auth/profiles/foo/bar" — the existing strings.Contains(rest,
// "/") check rejects it. The "url-encoded slash regression" sub-test
// exercises that decoded shape directly.
func TestProfileKeyFromPath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		suffix string
		want   string
	}{
		// Happy paths.
		{
			name:   "no suffix returns key",
			path:   "/api/auth/profiles/openai:default",
			suffix: "",
			want:   "openai:default",
		},
		{
			name:   "refresh suffix is trimmed",
			path:   "/api/auth/profiles/openai:default/refresh",
			suffix: "/refresh",
			want:   "openai:default",
		},

		// Multi-segment / traversal attempts must all return "".
		{
			name:   "multi-segment without suffix",
			path:   "/api/auth/profiles/foo/bar",
			suffix: "",
			want:   "",
		},
		{
			name:   "multi-segment with refresh suffix",
			path:   "/api/auth/profiles/foo/bar/refresh",
			suffix: "/refresh",
			want:   "",
		},
		{
			name:   "empty key after prefix",
			path:   "/api/auth/profiles/",
			suffix: "",
			want:   "",
		},
		{
			name:   "missing trailing slash on prefix",
			path:   "/api/auth/profiles",
			suffix: "",
			want:   "",
		},
		{
			name:   "extra segment before refresh suffix",
			path:   "/api/auth/profiles/openai:default/extra/refresh",
			suffix: "/refresh",
			want:   "",
		},

		// URL-encoded slash regression: ServeMux decodes %2F to "/"
		// before our handler runs, so the helper sees the decoded
		// path and the embedded slash check rejects it.
		{
			name:   "url-encoded slash decoded by mux",
			path:   "/api/auth/profiles/foo/bar",
			suffix: "",
			want:   "",
		},

		// Different prefix entirely.
		{
			name:   "different prefix",
			path:   "/api/scans/foo",
			suffix: "",
			want:   "",
		},

		// Suffix mismatch: caller asked for /refresh but the path
		// doesn't end in it.
		{
			name:   "missing required suffix",
			path:   "/api/auth/profiles/openai:default",
			suffix: "/refresh",
			want:   "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := profileKeyFromPath(tc.path, tc.suffix)
			if got != tc.want {
				t.Fatalf("profileKeyFromPath(%q, %q) = %q, want %q", tc.path, tc.suffix, got, tc.want)
			}
		})
	}
}
