package templates

import (
	"html/template"
	"io"
	"strings"
	"testing"
)

func TestTemplatesRender(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "*.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"console", "routes"} {
		if err := tmpl.ExecuteTemplate(io.Discard, name, map[string]string{"Title": name, "Base": "/app", "RouteHost": "", "RoutePath": ""}); err != nil {
			t.Errorf("rendering %s: %v", name, err)
		}
	}
}

// A route's address reaches the console's script as a quoted string.
func TestConsoleQuotesRouteAddress(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "*.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "console", map[string]string{"Title": "t", "Base": "", "RouteHost": `a";alert(1);"`, "RoutePath": "/p"}); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out.String(), `alert(1);"`) {
		t.Error("the route host wasn't escaped")
	}
	if !strings.Contains(out.String(), `const routeHost = "a\";alert(1);\"";`) {
		t.Errorf("unexpected routeHost line in %s", out.String()[strings.Index(out.String(), "const routeHost"):][:80])
	}
}
