package sshmuxer

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/vulcand/oxy/v2/roundrobin"
)

func newTestAliasHolder(t *testing.T, owners map[string][]string) *utils.AliasHolder {
	t.Helper()

	lb, err := roundrobin.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	aH := &utils.AliasHolder{
		AliasHost:      "private:3000",
		SSHConnections: syncmap.New[string, *utils.SSHConnection](),
		Balancer:       lb,
	}

	for addr, allowed := range owners {
		aH.SSHConnections.Store(addr, &utils.SSHConnection{TCPAliasesAllowedUsers: allowed})

		err := lb.UpsertServer(&url.URL{Host: base64.StdEncoding.EncodeToString([]byte(addr))})
		if err != nil {
			t.Fatal(err)
		}
	}

	return aH
}

func TestSelectAliasBackendHonorsSelectedOwner(t *testing.T) {
	aH := newTestAliasHolder(t, map[string][]string{
		"/tmp/a.sock": {"SHA256:a"},
		"/tmp/b.sock": {"SHA256:b"},
	})

	for range 10 {
		addr, err := selectAliasBackend(aH, "SHA256:b", true)
		if err != nil {
			t.Fatal(err)
		}

		if addr != "/tmp/b.sock" {
			t.Fatalf("fingerprint b routed to %s", addr)
		}
	}
}

func TestSelectAliasBackendAnyOnlyOpensItsOwnBackend(t *testing.T) {
	aH := newTestAliasHolder(t, map[string][]string{
		"/tmp/a.sock": {"SHA256:a"},
		"/tmp/b.sock": {"SHA256:b", "any"},
	})

	for range 10 {
		addr, err := selectAliasBackend(aH, "SHA256:other", true)
		if err != nil {
			t.Fatal(err)
		}

		if addr != "/tmp/b.sock" {
			t.Fatalf("unlisted fingerprint routed to %s", addr)
		}
	}
}

func TestSelectAliasBackendDeniesUnlisted(t *testing.T) {
	aH := newTestAliasHolder(t, map[string][]string{
		"/tmp/a.sock": {"SHA256:a"},
		"/tmp/b.sock": {"SHA256:b"},
	})

	for _, fingerprint := range []string{"SHA256:other", ""} {
		_, err := selectAliasBackend(aH, fingerprint, true)
		if !errors.Is(err, errAliasNotAllowed) {
			t.Fatalf("fingerprint %q: got err %v", fingerprint, err)
		}
	}
}

func TestSelectAliasBackendBalancesAllowedOwners(t *testing.T) {
	aH := newTestAliasHolder(t, map[string][]string{
		"/tmp/a.sock": {"SHA256:a", "SHA256:shared"},
		"/tmp/b.sock": {"SHA256:b", "SHA256:shared"},
		"/tmp/c.sock": {"SHA256:c"},
	})

	seen := map[string]int{}
	for range 10 {
		addr, err := selectAliasBackend(aH, "SHA256:shared", true)
		if err != nil {
			t.Fatal(err)
		}

		seen[addr]++
	}

	if seen["/tmp/a.sock"] == 0 || seen["/tmp/b.sock"] == 0 || seen["/tmp/c.sock"] != 0 {
		t.Fatalf("unexpected distribution %v", seen)
	}
}

func TestSelectAliasBackendWithoutAllowlistUsesAnyBackend(t *testing.T) {
	aH := newTestAliasHolder(t, map[string][]string{
		"/tmp/a.sock": {"SHA256:a"},
		"/tmp/b.sock": {"SHA256:b"},
	})

	seen := map[string]int{}
	for range 4 {
		addr, err := selectAliasBackend(aH, "", false)
		if err != nil {
			t.Fatal(err)
		}

		seen[addr]++
	}

	if len(seen) != 2 {
		t.Fatalf("unexpected distribution %v", seen)
	}
}
