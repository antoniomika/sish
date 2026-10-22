package httpmuxer

import "testing"

func TestRedactURI(t *testing.T) {
	cases := map[string]struct {
		uri    string
		tokens []string
		want   string
	}{
		"route token":       {"/_sish/console?x-authorization=abc123", []string{"", "abc123"}, "/_sish/console?x-authorization=[REDACTED]"},
		"unknown token":     {"/_sish/console/ws?x-authorization=guess", nil, "/_sish/console/ws?x-authorization=[REDACTED]"},
		"other params kept": {"/a?b=1&x-authorization=t&c=2", nil, "/a?b=1&x-authorization=[REDACTED]&c=2"},
		"escaped key":       {"/a?x%2Dauthorization=t", nil, "/a?x%2Dauthorization=[REDACTED]"},
		"token elsewhere":   {"/files/abc123?abc123", []string{"abc123"}, "/files/[REDACTED]?[REDACTED]"},
		"no query":          {"/plain", []string{"abc123"}, "/plain"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := redactURI(tc.uri, tc.tokens...); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
