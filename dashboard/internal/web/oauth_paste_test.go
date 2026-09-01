package web

import "testing"

// TestParsePastedAuthCode pins the normalization the paste-flow complete
// handler applies to whatever the operator copies out of the browser after
// sign-in: a full redirect URL, a bare query fragment, or a bare code.
func TestParsePastedAuthCode(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantCode  string
		wantState string
		wantOK    bool
	}{
		{
			name:      "full redirect URL",
			in:        "http://localhost:1455/auth/callback?code=ac_ABC123&state=st_XYZ",
			wantCode:  "ac_ABC123",
			wantState: "st_XYZ",
			wantOK:    true,
		},
		{
			name:      "full redirect URL 127.0.0.1 host",
			in:        "http://127.0.0.1:1455/auth/callback?code=ac_ABC123&state=st_XYZ",
			wantCode:  "ac_ABC123",
			wantState: "st_XYZ",
			wantOK:    true,
		},
		{
			name:      "url with trailing newline from copy-paste",
			in:        "http://localhost:1455/auth/callback?code=ac_ABC123&state=st_XYZ\n",
			wantCode:  "ac_ABC123",
			wantState: "st_XYZ",
			wantOK:    true,
		},
		{
			name:      "bare query fragment with leading ?",
			in:        "?code=ac_ABC123&state=st_XYZ",
			wantCode:  "ac_ABC123",
			wantState: "st_XYZ",
			wantOK:    true,
		},
		{
			name:      "bare query fragment no ?",
			in:        "code=ac_ABC123&state=st_XYZ",
			wantCode:  "ac_ABC123",
			wantState: "st_XYZ",
			wantOK:    true,
		},
		{
			name:     "bare code",
			in:       "ac_ABC123",
			wantCode: "ac_ABC123",
			wantOK:   true,
		},
		{
			name:     "bare code with surrounding whitespace",
			in:       "  ac_ABC123  ",
			wantCode: "ac_ABC123",
			wantOK:   true,
		},
		{
			name:   "empty input",
			in:     "   ",
			wantOK: false,
		},
		{
			name:   "free text with spaces declined",
			in:     "I could not find the code sorry",
			wantOK: false,
		},
		{
			name:      "url-encoded code value preserved",
			in:        "http://localhost:1455/auth/callback?code=ac%2Fwith%2Fslashes&state=s",
			wantCode:  "ac/with/slashes",
			wantState: "s",
			wantOK:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, state, ok := parsePastedAuthCode(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (code=%q state=%q)", ok, tc.wantOK, code, state)
			}
			if !ok {
				return
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
		})
	}
}
