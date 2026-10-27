package utils

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"time"
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
