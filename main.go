// Package main represents the main entrypoint of the sish application.
package main

import (
	"log/slog"

	"github.com/antoniomika/sish/cmd"
)

// main will start the sish command lifecycle and spawn the sish services.
func main() {
	err := cmd.Execute()
	if err != nil {
		slog.Error(
			"Unable to execute root command:",
			"error", err,
		)
	}
}
