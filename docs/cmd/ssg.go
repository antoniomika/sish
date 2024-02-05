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
				{Text: "Managed", Href: "#managed"},
				{Text: "DNS", Href: "#dns"},
				{Text: "Docker Compose", Href: "#docker-compose"},
				{Text: "Docker", Href: "#docker"},
				{Text: "Google Cloud Platform", Href: "#google-cloud-platform"},
				{Text: "Authentication", Href: "#authentication"},
			},
		},
		{
			Text: "How it Works",
			Href: "/how-it-works",
			Page: pager("how-it-works.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "Port Forward", Href: "#port-forward"},
				{Text: "Traditional VPN", Href: "#traditional-vpn"},
				{Text: "sish Public", Href: "#sish-public"},
				{Text: "sish Private", Href: "#sish-private"},
			},
		},
		{
			Text: "Forwarding Types",
			Href: "/forwarding-types",
			Page: pager("forwarding-types.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "HTTP", Href: "#href"},
				{Text: "TCP", Href: "#tcp"},
				{Text: "TCP Alias", Href: "#tcp-alias"},
				{Text: "SNI", Href: "#sni"},
			},
		},
		{
			Text: "Cheatsheet",
			Href: "/cheatsheet",
			Page: pager("cheatsheet.md"),
			Tag:  "Help",
			Children: []*pdocs.Sitemap{
				{Text: "Remote forward SSH tunnels", Href: "#remote-forward-ssh-tunnels"},
				{Text: "Local forward SSH tunnels", Href: "#local-foward-ssh-tunnels"},
				{Text: "HTTPS public access", Href: "#https-public-access"},
				{Text: "HTTPS private access", Href: "#https-private-access"},
				{Text: "Websocket", Href: "#websocket"},
				{Text: "TCP public access", Href: "#tcp-public-access"},
				{Text: "TCP private access", Href: "#tcp-private-access"},
			},
		},
		{Text: "CLI", Href: "/cli", Page: pager("cli.md"), Tag: "CLI"},
		{
			Text: "Advanced",
			Href: "/advanced",
			Page: pager("advanced.md"),
			Children: []*pdocs.Sitemap{
				{Text: "Choose your own subdomain", Href: "#choose-your-own-subdomain"},
				{Text: "Websocket Support", Href: "#websocket-support"},
				{Text: "Allowlist IPs", Href: "#allowlist-ips"},
				{Text: "Custom Domains", Href: "#custom-domains"},
				{Text: "Load Balancing", Href: "#load-balancing"},
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
