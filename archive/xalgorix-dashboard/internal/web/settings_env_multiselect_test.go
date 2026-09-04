package web

import "testing"

// oobInteractionsDef mirrors the XALGORIX_OOB_INTERACTIONS definition so the
// multiselect normalizer is tested against the real option set.
func oobInteractionsDef() envSettingDefinition {
	return envSettingDefinition{
		Key:       "XALGORIX_OOB_INTERACTIONS",
		InputType: "multiselect",
		Options:   []string{"dns", "http", "smtp"},
	}
}

func TestNormalizeMultiSelect(t *testing.T) {
	def := oobInteractionsDef()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"blank stays blank (all/default)", "", ""},
		{"every option collapses to blank (env stays unset)", "dns,http,smtp", ""},
		{"reordered full selection also collapses", "smtp,http,dns", ""},
		{"single option", "http", "http"},
		{"re-ordered to match def.Options", "smtp,dns", "dns,smtp"},
		{"duplicates are removed", "http,http", "http"},
		{"case and whitespace are canonicalized", " HTTP , SMTP ", "http,smtp"},
		{"empty entries are ignored", "http,,", "http"},
		{"only-commas means all/default", ",,", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMultiSelect(def, tt.value)
			if err != nil {
				t.Fatalf("normalizeMultiSelect(%q) returned error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMultiSelect(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestNormalizeMultiSelectRejectsUnknownOption(t *testing.T) {
	def := oobInteractionsDef()

	if _, err := normalizeMultiSelect(def, "http,ftp"); err == nil {
		t.Fatal("normalizeMultiSelect accepted an option outside def.Options")
	}
}

// The multiselect type must be reachable through the shared normalizer, since
// applyEnvironmentUpdates routes every value through normalizeEnvSettingValue.
func TestNormalizeEnvSettingValueHandlesMultiSelect(t *testing.T) {
	got, err := normalizeEnvSettingValue(oobInteractionsDef(), " SMTP , DNS ")
	if err != nil {
		t.Fatalf("normalizeEnvSettingValue returned error: %v", err)
	}
	if got != "dns,smtp" {
		t.Fatalf("normalizeEnvSettingValue = %q, want %q", got, "dns,smtp")
	}
}
