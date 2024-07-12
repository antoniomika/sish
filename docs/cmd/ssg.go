package main

import (
	"log/slog"

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

	config := &pdocs.DocConfig{
		Logger:   slog.Default(),
		Sitemap:  sitemap,
		Out:      "./docs/public",
		Tmpl:     "./docs/tmpl",
		PageTmpl: "post.page.tmpl",
	}

	err := config.GenSite()
	if err != nil {
		panic(err)
	}
}
