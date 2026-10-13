// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"serverdeck.local/agent/internal/app"
)

func main() { os.Exit(app.Run("serverdeck-agent", os.Args[1:], os.Stdout, os.Stderr)) }
