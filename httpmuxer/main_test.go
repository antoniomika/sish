package httpmuxer

import (
	"log/slog"
	"os"
	"testing"
)

// TestMain installs a real handler, since captureLog swaps handlers and
// slog's default routes through the log package.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	os.Exit(m.Run())
}
