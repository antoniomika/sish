package main

import (
	"github.com/picosh/pdocs"
)

func main() {
	pager := pdocs.Pager("./docs/posts")
	sitemap := []*pdocs.Sitemap{
		{Text: "Home", Href: "/", Page: pager("home.md")},
		{Text: "Sitemap", Href: "/sitemap", Page: pager("sitemap.md")},
		{
			Text: "Getting Started",
			Href: "/getting-started",
			Page: pager("getting-started.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "Managed"},
				{Text: "DNS"},
				{Text: "Docker Compose"},
				{Text: "Docker"},
				{Text: "Google Cloud Platform"},
				{Text: "Authentication"},
			},
		},
		{
			Text: "How it Works",
			Href: "/how-it-works",
			Page: pager("how-it-works.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "Port Forward"},
				{Text: "Traditional VPN"},
				{Text: "sish Public"},
				{Text: "sish Private"},
				{Text: "Additional Details"},
			},
		},
		{
			Text: "Forwarding Types",
			Href: "/forwarding-types",
			Page: pager("forwarding-types.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "HTTP"},
				{Text: "TCP"},
				{Text: "TCP Alias"},
				{Text: "SNI"},
			},
		},
		{
			Text: "Cheatsheet",
			Href: "/cheatsheet",
			Page: pager("cheatsheet.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "Remote forward SSH tunnels"},
				{Text: "Local forward SSH tunnels"},
				{Text: "HTTPS public access"},
				{Text: "HTTPS private access"},
				{Text: "Websocket"},
				{Text: "TCP public access"},
				{Text: "TCP private access"},
			},
		},
		{Text: "CLI", Href: "/cli", Page: pager("cli.md"), Tag: "CLI"},
		{
			Text: "Advanced",
			Href: "/advanced",
			Page: pager("advanced.md"),
			Children: []*pdocs.Sitemap{
				{Text: "Choose your own subdomain"},
				{Text: "Websocket Support"},
				{Text: "Allowlist IPs"},
				{Text: "Custom Domains"},
				{Text: "Load Balancing"},
			},
			Tag: "Help",
		},
		{Text: "FAQ", Href: "/faq", Page: pager("faq.md"), Tag: "Help"},
	}

	config := &pdocs.DocConfig{
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
