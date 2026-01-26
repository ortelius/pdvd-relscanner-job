// Package main is the entrypoint for the cli
package main

import "relscanner/cmd"

func main() {
	// Execute initializes the command structure and executes the root command.
	// All logic for the Kubernetes Job worker is handled within the cmd package.
	cmd.Execute()
}
