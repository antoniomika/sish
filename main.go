package main

import (
	"log"

	"github.com/antoniomika/sish/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("Unable to execute root command:", err)
	}
}
