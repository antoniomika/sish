// Package main represents the main entrypoint of the sish application.
package main

import (
	"log"

	"github.com/antoniomika/sish/cmd"
)

// main will start the sish command lifecycle and spawn the sish services.
func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("Unable to execute root command:", err)
	}
}
