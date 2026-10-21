// Package assets holds the stylesheets and icons shared by the consoles and the docs site.
package assets

import "embed"

// FS contains the shared stylesheets and icons.
//
//go:embed *.css *.svg *.png
var FS embed.FS
