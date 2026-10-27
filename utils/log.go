package utils

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Fatal logs msg at error level and exits, like log.Fatal does for the
// standard logger. The record carries the caller's source location.
func Fatal(msg string, args ...any) {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])

	r := slog.NewRecord(time.Now(), slog.LevelError, msg, pcs[0])
	r.Add(args...)
	_ = slog.Default().Handler().Handle(context.Background(), r)

	os.Exit(1)
}

// ZapLogger returns a zap logger that writes to the default slog logger, for
// libraries such as certmagic that log through zap.
func ZapLogger() *zap.Logger {
	return zap.New(slogCore{})
}

// slogCore is a zapcore.Core that sends entries to the default slog logger.
type slogCore struct {
	fields []zapcore.Field
}

func (c slogCore) Enabled(level zapcore.Level) bool {
	return slog.Default().Enabled(context.Background(), slogLevel(level))
}

func (c slogCore) With(fields []zapcore.Field) zapcore.Core {
	return slogCore{fields: slices.Concat(c.fields, fields)}
}

func (c slogCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}

	return checked
}

func (c slogCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, field := range slices.Concat(c.fields, fields) {
		field.AddTo(enc)
	}

	r := slog.NewRecord(entry.Time, slogLevel(entry.Level), entry.Message, 0)
	if entry.LoggerName != "" {
		r.AddAttrs(slog.String("logger", entry.LoggerName))
	}

	for _, key := range slices.Sorted(maps.Keys(enc.Fields)) {
		r.AddAttrs(slog.Any(key, enc.Fields[key]))
	}

	return slog.Default().Handler().Handle(context.Background(), r)
}

func (c slogCore) Sync() error {
	return nil
}

func slogLevel(level zapcore.Level) slog.Level {
	switch {
	case level <= zapcore.DebugLevel:
		return slog.LevelDebug
	case level == zapcore.InfoLevel:
		return slog.LevelInfo
	case level == zapcore.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}
