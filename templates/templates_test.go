package templates

import (
	"html/template"
	"io"
	"testing"
)

func TestTemplatesRender(t *testing.T) {
	tmpl, err := template.ParseFS(FS, "*.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"console", "routes"} {
		if err := tmpl.ExecuteTemplate(io.Discard, name, map[string]string{"Title": name, "Base": "/app"}); err != nil {
			t.Errorf("rendering %s: %v", name, err)
		}
	}
}
