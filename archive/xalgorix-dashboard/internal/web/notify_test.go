package web

import (
	"strings"
	"testing"
)

func TestDiscordMarkdownToTelegramHTML(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bold", "**Host Header Injection**", "<b>Host Header Injection</b>"},
		{"inline code", "endpoint `https://x/`", "endpoint <code>https://x/</code>"},
		{
			"label then value",
			"📊 **CVSS:** `3.4` | **Severity:** `LOW`",
			"📊 <b>CVSS:</b> <code>3.4</code> | <b>Severity:</b> <code>LOW</code>",
		},
		{
			"fenced block",
			"🧪 **PoC:**\n```\ncurl https://x\n```",
			"🧪 <b>PoC:</b>\n<pre>curl https://x\n</pre>",
		},
		{"escapes html then converts", "**<script>**", "<b>&lt;script&gt;</b>"},
		{"ampersand escaped", "a & b", "a &amp; b"},
		{"plain text untouched", "just text", "just text"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := discordMarkdownToTelegramHTML(c.in)
			if got != c.want {
				t.Fatalf("discordMarkdownToTelegramHTML(%q)\n got: %q\nwant: %q", c.in, got, c.want)
			}
			// No raw Discord bold markers should survive.
			if strings.Contains(got, "**") {
				t.Fatalf("raw ** survived conversion: %q", got)
			}
		})
	}
}

func TestTelegramFormatConvertsBody(t *testing.T) {
	out := telegramFormat("🐛 LOW Vulnerability Found", "**Title**\n🔗 **Endpoint:** `https://x/`")
	if strings.Contains(out, "**") {
		t.Fatalf("telegramFormat left raw markdown: %q", out)
	}
	if !strings.HasPrefix(out, "<b>🐛 LOW Vulnerability Found</b>\n") {
		t.Fatalf("title not bolded: %q", out)
	}
	if !strings.Contains(out, "<b>Title</b>") || !strings.Contains(out, "<code>https://x/</code>") {
		t.Fatalf("body not converted: %q", out)
	}
}
