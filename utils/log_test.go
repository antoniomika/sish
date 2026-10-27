package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestZapLoggerWritesToSlog(t *testing.T) {
	var buf bytes.Buffer

	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	logger := ZapLogger().Named("certmagic").With(zap.String("issuer", "acme"))
	logger.Debug("filtered by the slog level")
	logger.Warn("renewing certificate", zap.Strings("identifiers", []string{"example.com"}), zap.Error(errors.New("rate limited")))

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("expected one JSON record, got %q: %v", buf.String(), err)
	}

	expected := map[string]any{
		"level":       "WARN",
		"msg":         "renewing certificate",
		"logger":      "certmagic",
		"issuer":      "acme",
		"identifiers": []any{"example.com"},
		"error":       "rate limited",
	}
	for key, value := range expected {
		got, _ := json.Marshal(record[key])
		want, _ := json.Marshal(value)
		if !bytes.Equal(got, want) {
			t.Errorf("expected %s=%s, got %s", key, want, got)
		}
	}
}

func TestFormatLog(t *testing.T) {
	conn := &SSHConnection{}

	if got := conn.FormatLog(slog.LevelInfo, "rich text\r\n", "msg", "key", "value"); got != "rich text\r\n" {
		t.Errorf("expected the text by default, got %q", got)
	}

	conn.JSONLogs.Store(true)

	if got := conn.FormatLog(slog.LevelInfo, "text only\r\n", ""); got != "" {
		t.Errorf("expected a message without msg to be dropped, got %q", got)
	}

	got := conn.FormatLog(slog.LevelWarn, "rich text\r\n", "port unavailable", "port", 80)
	if !strings.HasSuffix(got, "}\r\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("expected one JSON line ending in CRLF, got %q", got)
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(got), &record); err != nil {
		t.Fatalf("expected a JSON record, got %q: %v", got, err)
	}

	if record["level"] != "WARN" || record["msg"] != "port unavailable" || record["port"] != float64(80) {
		t.Errorf("unexpected record %v", record)
	}
}
