// Package templates holds the HTML templates for the admin and service consoles.
package templates

import "embed"

// FS contains the built-in console templates.
//
//go:embed *.tmpl
var FS embed.FS
