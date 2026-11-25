package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/picosh/pdocs"
)

func main() {
	pager := pdocs.Pager("./docs/posts")
	sitemap := &pdocs.Sitemap{
		Children: []*pdocs.Sitemap{
			{Text: "Home", Href: "/", Page: pager("home.md")},
			{Text: "Sitemap", Href: "/sitemap", Page: pager("sitemap.md")},
			{
				Text: "Getting Started",
				Href: "/getting-started",
				Page: pager("getting-started.md"),
			},
			{
				Text: "How it Works",
				Href: "/how-it-works",
				Page: pager("how-it-works.md"),
			},
			{
				Text: "Forwarding Types",
				Href: "/forwarding-types",
				Page: pager("forwarding-types.md"),
			},
			{
				Text: "Cheatsheet",
				Href: "/cheatsheet",
				Page: pager("cheatsheet.md"),
			},
			{Text: "CLI", Href: "/cli", Page: pager("cli.md")},
			{
				Text: "Advanced",
				Href: "/advanced",
				Page: pager("advanced.md"),
			},
			{Text: "FAQ", Href: "/faq", Page: pager("faq.md")},
		},
	}

	cacheID, err := staticHash()
	if err != nil {
		panic(err)
	}

	config := &pdocs.DocConfig{
		Logger:   slog.Default(),
		Sitemap:  sitemap,
		Out:      "./docs/public",
		Tmpl:     "./docs/tmpl",
		PageTmpl: "post.page.tmpl",
		CacheId:  cacheID,
	}

	err = config.GenSite()
	if err != nil {
		panic(err)
	}
}

func staticHash() (string, error) {
	files, err := filepath.Glob("./docs/static/*")
	if err != nil {
		return "", err
	}
	files = append(files, "./assets/smol.css", "./assets/syntax.css", "./assets/theme.css")
	h := sha256.New()
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		h.Write([]byte(file))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:8], nil
}
