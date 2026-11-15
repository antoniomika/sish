// Package utils implements utilities used across different
// areas of the sish application. There are utility functions
// that help with overall state management and are core to the application.
package utils

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniomika/syncmap"
	"github.com/caddyserver/certmagic"
	"github.com/jpillora/ipfilter"
	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
	"github.com/radovskyb/watcher"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
	"golang.org/x/crypto/ssh"
)

const (
	// sishDNSPrefix is the prefix used for DNS TXT records.
	sishDNSPrefix = "_sish"

	// Prefix used for defining wildcard host matchers.
	wildcardPrefix = "*."

	// maxBindAttempts bounds how many names a binding tries before it fails.
	maxBindAttempts = 100

	// maxAuthRequests bounds how many auth requests to an external service run at once.
	maxAuthRequests = 64
)

var (
	// Filter is the IPFilter used to block connections.
	Filter *ipfilter.IPFilter

	// certHolder is a slice of publickeys for auth.
	certHolder = make([]ssh.PublicKey, 0)

	// holderLock is the mutex used to update the certHolder slice.
	holderLock = sync.Mutex{}

	// bannedSubdomainList is a list of subdomains that cannot be bound.
	bannedSubdomainList = []string{""}

	// bannedAliasList is a list of aliases that cannot be bound.
	bannedAliasList = []string{""}

	// trustedUpstreams are the sources allowed to send a proxy protocol header. Empty trusts all.
	trustedUpstreams []netip.Prefix

	// authRequests holds a slot for each auth request to an external service in flight.
	authRequests = make(chan struct{}, maxAuthRequests)
)

// Setup main utils. This initializes whitelists and blacklists.
func Setup() {
	upperList := func(stringList string) []string {
		list := strings.FieldsFunc(stringList, CommaSplitFields)
		for k, v := range list {
			list[k] = strings.ToUpper(v)
		}

		return list
	}

	whitelistedCountriesList := upperList(viper.GetString("whitelisted-countries"))
	whitelistedIPList := strings.FieldsFunc(viper.GetString("whitelisted-ips"), CommaSplitFields)

	ipfilterOpts := ipfilter.Options{
		BlockedCountries: upperList(viper.GetString("banned-countries")),
		AllowedCountries: whitelistedCountriesList,
		BlockedIPs:       strings.FieldsFunc(viper.GetString("banned-ips"), CommaSplitFields),
		AllowedIPs:       whitelistedIPList,
		BlockByDefault:   len(whitelistedIPList) > 0 || len(whitelistedCountriesList) > 0,
	}

	if viper.GetBool("geodb") {
		Filter = ipfilter.NewLazy(ipfilterOpts)
	} else {
		Filter = ipfilter.NewNoDB(ipfilterOpts)
	}

	bannedSubdomainList = append(bannedSubdomainList, strings.FieldsFunc(viper.GetString("banned-subdomains"), CommaSplitFields)...)
	for k, v := range bannedSubdomainList {
		bannedSubdomainList[k] = strings.ToLower(strings.TrimSpace(v) + "." + viper.GetString("domain"))
	}

	bannedAliasList = append(bannedAliasList, strings.FieldsFunc(viper.GetString("banned-aliases"), CommaSplitFields)...)
	for k, v := range bannedAliasList {
		bannedAliasList[k] = strings.ToLower(strings.TrimSpace(v))
	}

	if portRange := viper.GetString("port-bind-range"); portRange != "" {
		if _, err := parsePortRanges(portRange); err != nil {
			Fatal(
				"invalid port-bind-range",
				"portBindRange", portRange,
				"err", err,
			)
		}
	}

	trustedUpstreams = nil
	for _, upstream := range strings.FieldsFunc(viper.GetString("proxy-protocol-trusted-upstreams"), CommaSplitFields) {
		prefix, err := ParsePrefix(strings.TrimSpace(upstream))
		if err != nil {
			Fatal(
				"invalid proxy-protocol-trusted-upstreams entry",
				"upstream", upstream,
				"err", err,
			)
		}

		trustedUpstreams = append(trustedUpstreams, prefix)
	}
}

// ParsePrefix parses an IP or CIDR into a prefix.
func ParsePrefix(upstream string) (netip.Prefix, error) {
	if strings.Contains(upstream, "/") {
		prefix, err := netip.ParsePrefix(upstream)
		return prefix.Masked(), err
	}

	addr, err := netip.ParseAddr(upstream)
	if err != nil {
		return netip.Prefix{}, err
	}

	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}

// upstreamTrusted reports whether a proxy protocol header from addr may be used.
func upstreamTrusted(addr net.Addr) bool {
	if len(trustedUpstreams) == 0 {
		return true
	}

	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}

	ip := addrPort.Addr().Unmap()
	for _, prefix := range trustedUpstreams {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// CommaSplitFields is a function used by strings.FieldsFunc to split around commas.
func CommaSplitFields(c rune) bool {
	return c == ','
}

// LoadProxyProtoConfig will load the timeouts and policies for the proxy protocol.
func LoadProxyProtoConfig(l *proxyproto.Listener) {
	if viper.GetBool("proxy-protocol-use-timeout") {
		l.ReadHeaderTimeout = viper.GetDuration("proxy-protocol-timeout")
	}

	l.ConnPolicy = func(connPolicyOptions proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		if !upstreamTrusted(connPolicyOptions.Upstream) {
			// Untrusted sources can connect directly but can't set their address.
			if viper.GetString("proxy-protocol-policy") == "require" {
				return proxyproto.REJECT, fmt.Errorf("%w: %s", proxyproto.ErrInvalidUpstream, connPolicyOptions.Upstream)
			}

			return proxyproto.REJECT, nil
		}

		switch viper.GetString("proxy-protocol-policy") {
		case "ignore":
			return proxyproto.IGNORE, nil
		case "reject":
			return proxyproto.REJECT, nil
		case "require":
			return proxyproto.REQUIRE, nil
		}

		return proxyproto.USE, nil
	}
}

// portRange is an inclusive range of ports.
type portRange struct {
	low, high uint32
}

// parsePortRanges parses a comma separated list of ports and inclusive port ranges.
func parsePortRanges(portRanges string) ([]portRange, error) {
	parsePort := func(s string) (uint32, error) {
		port, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
		return uint32(port), err
	}

	ranges := []portRange{}
	for _, r := range strings.Split(strings.TrimSpace(portRanges), ",") {
		lowString, highString, isRange := strings.Cut(strings.TrimSpace(r), "-")

		low, err := parsePort(lowString)
		if err != nil {
			return nil, err
		}

		high := low
		if isRange {
			high, err = parsePort(highString)
			if err != nil {
				return nil, err
			}
		}

		if low > high {
			return nil, fmt.Errorf("port range %q is reversed", r)
		}

		ranges = append(ranges, portRange{low: low, high: high})
	}

	return ranges, nil
}

// GetRandomPortInRange returns a random port in the provided range that can
// be listened on. The port range is a comma separated list of ranges or ports.
func GetRandomPortInRange(listenAddr string, portRanges string) (uint32, error) {
	ranges, err := parsePortRanges(portRanges)
	if err != nil {
		return 0, err
	}

	total := uint64(0)
	for _, r := range ranges {
		total += uint64(r.high-r.low) + 1
	}

	portAt := func(i uint64) uint32 {
		for _, r := range ranges {
			size := uint64(r.high-r.low) + 1
			if i < size {
				return r.low + uint32(i)
			}
			i -= size
		}

		return 0
	}

	// Try each port once, starting from a random offset.
	start := mathrand.Uint64N(total)
	for i := range total {
		port := portAt((start + i) % total)

		ln, err := Listen(GenerateAddress(listenAddr, port))
		if err != nil {
			continue
		}

		err = ln.Close()
		if err != nil {
			slog.Error(
				"error closing listener",
				"err", err,
			)
		}

		return port, nil
	}

	return 0, fmt.Errorf("no free port in port-bind-range")
}

// CheckPort verifies if a port exists within the port range.
// It will return 0 and an error if not (0 allows the kernel to select)
// the port.
func CheckPort(port uint32, portRanges string) (uint32, error) {
	ranges, err := parsePortRanges(portRanges)
	if err != nil {
		return 0, err
	}

	for _, r := range ranges {
		if port >= r.low && port <= r.high {
			return port, nil
		}
	}

	return 0, fmt.Errorf("not a safe port")
}

func loadCerts(certManager *certmagic.Config) {
	certFiles, err := filepath.Glob(filepath.Join(viper.GetString("https-certificate-directory"), "*.crt"))
	if err != nil {
		slog.Error(
			"error loading unmanaged certificates",
			"err", err,
		)
	}

	ctx := context.TODO()

	for _, v := range certFiles {
		_, err := certManager.CacheUnmanagedCertificatePEMFile(ctx, v, fmt.Sprintf("%s.key", strings.TrimSuffix(v, ".crt")), []string{})
		if err != nil {
			slog.Error(
				"error loading unmanaged certificates",
				"err", err,
			)
		}
	}
}

func loadPrivateKeys(config *ssh.ServerConfig) {
	count := 0

	parseKey := func(data []byte, directory fs.DirEntry) {
		key, err := ssh.ParsePrivateKey(data)

		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			key, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(viper.GetString("private-key-passphrase")))
		}

		if err != nil {
			slog.Error(
				"error parsing private key file",
				"key", directory.Name(),
				"err", err,
			)
			return
		}

		slog.Info(
			"loading private key",
			"key", directory.Name(),
			"type", key.PublicKey().Type(),
		)

		config.AddHostKey(key)
		count++
	}

	err := filepath.WalkDir(viper.GetString("private-keys-directory"), func(path string, d fs.DirEntry, err error) error {
		if err != nil && d == nil {
			// This is likely an error with the directory we are walking (such as it not existing)
			return err
		}

		if d.IsDir() {
			return nil
		}

		if err != nil {
			slog.Error(
				"error walking directory for private key",
				"dirEntry", d.Name(),
				"err", err,
			)
			return nil
		}

		i, e := os.ReadFile(path)
		if e != nil {
			slog.Error(
				"can't read file for private key",
				"dirEntry", d.Name(),
				"err", e,
			)
			return nil
		}

		if len(i) > 0 {
			parseKey(i, d)
		}

		return nil
	})

	if err != nil {
		slog.Error(
			"unable to walk private-keys-directory",
			"directory", viper.GetString("private-keys-directory"),
			"err", err,
		)
	}

	if count == 0 {
		config.AddHostKey(loadPrivateKey(viper.GetString("private-key-passphrase")))
	}
}

// WatchCerts watches https certs for changes and will load them.
func WatchCerts(certManager *certmagic.Config) {
	loadCerts(certManager)

	w := watcher.New()
	w.SetMaxEvents(1)

	if err := w.AddRecursive(viper.GetString("https-certificate-directory")); err != nil {
		Fatal(
			"unable to watch https certificate directory",
			"err", err,
		)
	}

	go func() {
		w.Wait()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for range c {
				w.Close()
				os.Exit(0)
			}
		}()

		for {
			select {
			case _, ok := <-w.Event:
				if !ok {
					return
				}
				loadCerts(certManager)
			case _, ok := <-w.Error:
				if !ok {
					return
				}
			}
		}
	}()

	go func() {
		if err := w.Start(viper.GetDuration("https-certificate-directory-watch-interval")); err != nil {
			Fatal(
				"unable to start https certificate directory watcher",
				"err", err,
			)
		}
	}()
}

// WatchKeys watches ssh keys for changes and will load them.
func WatchKeys() {
	loadKeys()

	w := watcher.New()
	w.SetMaxEvents(1)

	if err := w.AddRecursive(viper.GetString("authentication-keys-directory")); err != nil {
		Fatal(
			"unable to watch authentication keys directory",
			"err", err,
		)
	}

	go func() {
		w.Wait()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for range c {
				w.Close()
				os.Exit(0)
			}
		}()

		for {
			select {
			case _, ok := <-w.Event:
				if !ok {
					return
				}
				loadKeys()
			case _, ok := <-w.Error:
				if !ok {
					return
				}
			}
		}
	}()

	go func() {
		if err := w.Start(viper.GetDuration("authentication-keys-directory-watch-interval")); err != nil {
			Fatal(
				"unable to start authentication keys directory watcher",
				"err", err,
			)
		}
	}()
}

// loadKeys loads public keys from the keys directory into a slice that is used
// authenticating a user.
func loadKeys() {
	tmpCertHolder := make([]ssh.PublicKey, 0)

	parseKey := func(keyBytes []byte, d fs.DirEntry) {
		keyHandle := func(keyBytes []byte, d fs.DirEntry) []byte {
			key, _, _, rest, e := ssh.ParseAuthorizedKey(keyBytes)
			if e != nil {
				if e.Error() != "ssh: no key found" || (e.Error() == "ssh: no key found" && viper.GetBool("debug")) {
					slog.Debug(
						"can't load file as public key",
						"dirEntry", d.Name(),
						"keyBytes", keyBytes,
						"err", e,
					)
				}
			}

			if key != nil {
				tmpCertHolder = append(tmpCertHolder, key)
			}
			return rest
		}

		for ok := true; ok; ok = len(keyBytes) > 0 {
			keyBytes = keyHandle(keyBytes, d)
		}
	}

	err := filepath.WalkDir(viper.GetString("authentication-keys-directory"), func(path string, d fs.DirEntry, err error) error {
		if err != nil && d == nil {
			// Directory we are walking is missing or otherwise unreadable.
			return err
		}

		if d.IsDir() {
			return nil
		}

		if err != nil {
			slog.Error(
				"error walking file for public key",
				"dirEntry", d.Name(),
				"err", err,
			)
			return nil
		}

		i, e := os.ReadFile(path)
		if e != nil {
			slog.Error(
				"can't read file for public key",
				"dirEntry", d.Name(),
				"err", e,
			)
			return nil
		}

		if len(i) > 0 {
			parseKey(i, d)
		}

		return nil
	})

	if err != nil {
		slog.Error(
			"error walking authentication-keys-directory",
			"directory", viper.GetString("authentication-keys-directory"),
			"err", err,
		)
		return
	}

	holderLock.Lock()
	defer holderLock.Unlock()
	certHolder = tmpCertHolder
}

// GetSSHConfig Returns an SSH config for the ssh muxer.
// It handles auth and storing user connection information.
func GetSSHConfig() *ssh.ServerConfig {
	sshConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-sish",
		NoClientAuth:  !viper.GetBool("authentication"),
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			slog.Info(
				"login attempt",
				"remoteAddr", c.RemoteAddr().String(),
				"user", c.User(),
			)

			if expected := viper.GetString("authentication-password"); expected != "" && subtle.ConstantTimeCompare(password, []byte(expected)) == 1 {
				return nil, nil
			}

			// Allow validation of passwords via a sub-request to another service
			authUrl := viper.GetString("authentication-password-request-url")
			if authUrl != "" {
				validKey, err := checkAuthenticationPasswordRequest(authUrl, password, c.RemoteAddr(), c.User())
				if err != nil {
					slog.Error(
						"error calling authentication password url",
						"authURL", authUrl,
						"err", err,
					)
				}
				if validKey {
					return nil, nil
				}
			}

			return nil, fmt.Errorf("password doesn't match")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			authKey := ssh.MarshalAuthorizedKey(key)
			authKey = authKey[:len(authKey)-1]

			slog.Info(
				"login attempt",
				"remoteAddr", c.RemoteAddr().String(),
				"user", c.User(),
				"key", authKey,
			)

			// loadKeys replaces the slice, so a copy of the reference is safe to
			// range over without holding the lock through the auth request below.
			holderLock.Lock()
			keys := certHolder
			holderLock.Unlock()

			for _, i := range keys {
				if bytes.Equal(key.Marshal(), i.Marshal()) {
					permssionsData := &ssh.Permissions{
						Extensions: map[string]string{
							"pubKey":            string(authKey),
							"pubKeyFingerprint": ssh.FingerprintSHA256(key),
						},
					}

					return permssionsData, nil
				}
			}

			// Allow validation of public keys via a sub-request to another service
			authUrl := viper.GetString("authentication-key-request-url")
			if authUrl != "" {
				validKey, err := checkAuthenticationKeyRequest(authUrl, authKey, c.RemoteAddr(), c.User())
				if err != nil {
					slog.Error(
						"error calling authentication key url",
						"authURL", authUrl,
						"err", err,
					)
				}
				if validKey {
					permssionsData := &ssh.Permissions{
						Extensions: map[string]string{
							"pubKey":            string(authKey),
							"pubKeyFingerprint": ssh.FingerprintSHA256(key),
						},
					}
					return permssionsData, nil
				}
			}

			return nil, fmt.Errorf("public key doesn't match")
		},
	}

	if viper.GetString("authentication-password") == "" && viper.GetString("authentication-password-request-url") == "" {
		sshConfig.PasswordCallback = nil
	}

	loadPrivateKeys(sshConfig)

	return sshConfig
}

// checkAuthenticationKeyRequest makes an HTTP POST request to the specified url with
// the provided ssh public key in OpenSSH 'authorized keys' format to validate
// whether it should be accepted.
func checkAuthenticationKeyRequest(authUrl string, authKey []byte, addr net.Addr, user string) (bool, error) {
	parsedUrl, err := url.ParseRequestURI(authUrl)
	if err != nil {
		return false, fmt.Errorf("error parsing url %s", err)
	}

	release, err := acquireAuthRequest(viper.GetDuration("authentication-key-request-timeout"))
	if err != nil {
		return false, err
	}
	defer release()

	c := &http.Client{
		Timeout:       viper.GetDuration("authentication-key-request-timeout"),
		CheckRedirect: noRedirects,
	}
	urlS := parsedUrl.String()
	reqBodyMap := map[string]string{
		"auth_key":    string(authKey),
		"remote_addr": addr.String(),
		"user":        user,
	}
	reqBody, err := json.Marshal(reqBodyMap)
	if err != nil {
		return false, fmt.Errorf("error jsonifying request body")
	}
	res, err := c.Post(urlS, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}
	defer closeBody(res.Body)

	if res.StatusCode != http.StatusOK {
		slog.Info(
			"public key rejected by auth service",
			"authURL", urlS,
			"status", res.StatusCode,
		)
		return false, nil
	}

	return true, nil
}

// checkAuthenticationPasswordRequest makes an HTTP POST request to the specified url with
// the provided user-password pair to validate whether it should be accepted.
func checkAuthenticationPasswordRequest(authUrl string, password []byte, addr net.Addr, user string) (bool, error) {
	parsedUrl, err := url.ParseRequestURI(authUrl)
	if err != nil {
		return false, fmt.Errorf("error parsing url %s", err)
	}

	release, err := acquireAuthRequest(viper.GetDuration("authentication-password-request-timeout"))
	if err != nil {
		return false, err
	}
	defer release()

	c := &http.Client{
		Timeout:       viper.GetDuration("authentication-password-request-timeout"),
		CheckRedirect: noRedirects,
	}
	urlS := parsedUrl.String()
	reqBodyMap := map[string]string{
		"password":    string(password),
		"remote_addr": addr.String(),
		"user":        user,
	}
	reqBody, err := json.Marshal(reqBodyMap)
	if err != nil {
		return false, fmt.Errorf("error jsonifying request body")
	}
	res, err := c.Post(urlS, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}
	defer closeBody(res.Body)

	if res.StatusCode != http.StatusOK {
		slog.Info(
			"password rejected by auth service",
			"authURL", urlS,
			"status", res.StatusCode,
		)
		return false, nil
	}

	return true, nil
}

// acquireAuthRequest waits up to timeout for a free auth request slot, so
// clients that can't log in can't send the auth service unlimited requests.
func acquireAuthRequest(timeout time.Duration) (func(), error) {
	release := func() { <-authRequests }

	select {
	case authRequests <- struct{}{}:
		return release, nil
	default:
	}

	if timeout <= 0 {
		authRequests <- struct{}{}
		return release, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case authRequests <- struct{}{}:
		return release, nil
	case <-timer.C:
		return nil, fmt.Errorf("too many auth requests in flight")
	}
}

// noRedirects makes an auth request answer with the configured endpoint's own
// status, since a redirect to a page that returns 200 would approve the login.
func noRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// closeBody drains and closes a response body so its connection can be reused.
func closeBody(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<16))
	_ = body.Close()
}

// generatePrivateKey creates a new ed25519 private key to be used by the
// the SSH server as the host key.
func generatePrivateKey(passphrase string) []byte {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		Fatal(
			"unable to generate private key",
			"err", err,
		)
	}

	slog.Info("generated ED25519 keypair")

	// In an effort to guarantee that keys can still be loaded by OpenSSH
	// we adopt branching logic here for passphrase encrypted keys.
	// I wrote a module that handled both, but ultimately decided this
	// is likely cleaner and less specialized.
	var pemData []byte
	if passphrase != "" {
		pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(pk, "", []byte(passphrase))
		if err != nil {
			Fatal(
				"unable to marshal private key",
				"err", err,
			)
		}
		pemData = pem.EncodeToMemory(pemBlock)
	} else {
		pemBlock, err := ssh.MarshalPrivateKey(pk, "")
		if err != nil {
			Fatal(
				"unable to marshal private key",
				"err", err,
			)
		}
		pemData = pem.EncodeToMemory(pemBlock)
	}

	err = os.WriteFile(filepath.Join(viper.GetString("private-keys-directory"), "ssh_key"), pemData, 0600)
	if err != nil {
		slog.Error(
			"error writing to file",
			"err", err,
		)
	}

	return pemData
}

// ParsePrivateKey parses the PrivateKey into a ssh.Signer and
// let's it be used by the SSH server.
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := os.ReadFile(filepath.Join(viper.GetString("private-keys-directory"), "ssh_key"))
	if err != nil {
		slog.Error(
			"error loading private key, generating a new one",
			"err", err,
		)
		pk = generatePrivateKey(passphrase)
	}

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pk, []byte(passphrase))
		if err != nil {
			Fatal(
				"unable to parse private key",
				"err", err,
			)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pk)
		if err != nil {
			Fatal(
				"unable to parse private key",
				"err", err,
			)
		}
	}

	return signer
}

// inList is used to scan whether or not something exists
// in a slice of data.
func inList(host string, bannedList []string) bool {
	for _, v := range bannedList {
		if strings.TrimSpace(v) == host {
			return true
		}
	}

	return false
}

// verifyDNS will verify that a specific domain/subdomain combo matches
// the specific TXT entry that exists for the domain. It will check that the
// publickey used for auth is at least included in the TXT records for the domain.
func verifyDNS(addr string, sshConn *SSHConnection) (bool, string, error) {
	if !viper.GetBool("verify-dns") || sshConn.SSHConn.Permissions == nil {
		return false, "", nil
	}

	if _, ok := sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"]; !ok {
		return false, "", nil
	}

	// The trailing dot keeps the resolver from retrying the name under its search domains.
	records, err := net.LookupTXT(fmt.Sprintf("%s.%s.", sishDNSPrefix, strings.TrimSuffix(addr, ".")))

	for _, v := range records {
		match := sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"] == v
		if match {
			return match, v, err
		}
	}

	return false, "", nil
}

// GetOpenPort returns open ports that can be bound. It verifies the host to
// bind the port to and attempts to listen to the port to ensure it is open.
// If load balancing is enabled, it will return the port if used.
func GetOpenPort(addr string, port uint32, state *State, sshConn *SSHConnection, sniProxyEnabled bool) (string, uint32, *TCPHolder, error) {
	getUnusedPort := func() (string, uint32, *TCPHolder, error) {
		var tH *TCPHolder
		var bindErr error

		first := true
		bindPort := port
		bindAddr := addr
		listenAddr := ""

		// An SNI forward's requested address is its hostname, which isn't an address to listen on.
		if bindAddr == "" || sniProxyEnabled {
			bindAddr = sshConn.TCPAddress
		}

		if bindAddr == "" || (IsLocalhost(bindAddr) && viper.GetBool("localhost-as-all")) || viper.GetBool("force-tcp-address") {
			bindAddr = viper.GetString("tcp-address")
		} else if bindAddr != "localhost" && net.ParseIP(bindAddr) == nil {
			// Anything else would reach the listener as a network or address list.
			return "", 0, nil, fmt.Errorf("invalid tcp address %q", bindAddr)
		}

		// Port 0 asks for any port, so it is never unavailable.
		reportUnavailable := func(unavailable bool) {
			if first && unavailable && port != 0 {
				extra := " Assigning a random port."
				if viper.GetBool("force-requested-ports") {
					extra = ""

					bindErr = fmt.Errorf("unable to bind requested port")
				}

				sshConn.SendLog(
					slog.LevelWarn,
					aurora.Sprintf("The TCP port %d is unavailable.%s", aurora.Red(bindPort), extra),
					"port unavailable",
					"port", bindPort,
					"assigningRandom", extra != "",
				)
			}
		}

		checkPort := func(checkerPort uint32) bool {
			if bindErr != nil {
				return false
			}

			listenAddr = GenerateAddress(bindAddr, bindPort)
			checkedPort, err := CheckPort(checkerPort, viper.GetString("port-bind-range"))
			_, ok := state.TCPListeners.Load(listenAddr)

			if err == nil && !ok && (viper.GetBool("tcp-load-balancer") || viper.GetBool("sni-load-balancer")) {
				ln, listenErr := Listen(listenAddr)
				if listenErr != nil {
					err = listenErr
				} else {
					err := ln.Close()
					if err != nil {
						slog.Error(
							"error closing listener",
							"err", err,
						)
					}
				}
			}

			if viper.GetBool("bind-random-ports") || !first || err != nil {
				reportUnavailable(true)

				if viper.GetString("port-bind-range") != "" {
					randomPort, err := GetRandomPortInRange(bindAddr, viper.GetString("port-bind-range"))
					if err != nil {
						bindErr = err
						return false
					}

					bindPort = randomPort
				} else {
					bindPort = 0
				}
			} else {
				bindPort = checkedPort
			}

			listenAddr = GenerateAddress(bindAddr, bindPort)
			holder, ok := state.TCPListeners.Load(listenAddr)
			if ok && ((!sniProxyEnabled && viper.GetBool("tcp-load-balancer")) || sniProxyEnabled) {
				tH = holder
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkPort(bindPort) {
		}

		return listenAddr, bindPort, tH, bindErr
	}

	return getUnusedPort()
}

// validBindHost reports whether host is a hostname, optionally with a leading wildcard label.
func validBindHost(host string) bool {
	host = strings.TrimPrefix(host, wildcardPrefix)
	if host == "" || len(host) > 253 {
		return false
	}

	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}

	return true
}

// validURLPart reports whether s only uses characters a URL can carry as-is in
// its userinfo or path. allowColon is false for a username, where ':' would
// start the password.
func validURLPart(s string, allowColon bool) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-._~!$&'()*+,;=", r):
		case r == ':' && allowColon:
		default:
			return false
		}
	}

	return true
}

// IsLocalhost reports whether addr is localhost or a loopback IP.
func IsLocalhost(addr string) bool {
	if addr == "localhost" {
		return true
	}

	ip := net.ParseIP(addr)

	return ip != nil && ip.IsLoopback()
}

// hostsOverlap reports whether two bound hosts would receive the same names.
func hostsOverlap(a, b string) bool {
	return a == b || MatchesWildcardHost(a, b) || MatchesWildcardHost(b, a)
}

// httpsSNIBound reports whether host overlaps an SNI name bound on sish's HTTPS port.
func httpsSNIBound(state *State, host string) bool {
	bound := false

	state.TCPListeners.Range(func(_ string, tH *TCPHolder) bool {
		if !tH.HTTPS {
			return true
		}

		tH.Balancers.Range(func(name string, _ *roundrobin.RoundRobin) bool {
			bound = name != "" && hostsOverlap(host, name)
			return !bound
		})

		return !bound
	})

	return bound
}

// httpBindingConflict returns the listener with the same host and credentials
// that a binding could join, and whether the binding is taken. Bindings at the
// same host and path can each have their own credentials, which pick between
// them. Any other overlap with an HTTP host or an HTTPS SNI name is taken.
func httpBindingConflict(state *State, host, path, username, password string) (*HTTPHolder, bool) {
	var holder *HTTPHolder
	taken := false

	state.HTTPListeners.Range(func(key string, locationListener *HTTPHolder) bool {
		if host != locationListener.HTTPUrl.Host || !strings.HasPrefix(path, locationListener.HTTPUrl.Path) {
			return true
		}

		parsedPassword, _ := locationListener.HTTPUrl.User.Password()
		if username == locationListener.HTTPUrl.User.Username() && password == parsedPassword {
			holder = locationListener
			taken = true
			return true
		}

		bothNeedCredentials := username != "" && password != "" && locationListener.HTTPUrl.User.Username() != "" && parsedPassword != ""
		if !bothNeedCredentials || path != locationListener.HTTPUrl.Path {
			taken = true
		}

		return true
	})

	return holder, taken || httpsSNIBound(state, host)
}

// HTTPBindingTaken reports whether a new HTTP listener for u would overlap an existing binding.
func HTTPBindingTaken(state *State, u *url.URL) bool {
	password, _ := u.User.Password()
	_, taken := httpBindingConflict(state, u.Host, u.Path, u.User.Username(), password)

	return taken
}

// HTTPHostBound reports whether host overlaps the root domain or a bound HTTP host.
func HTTPHostBound(state *State, host string) bool {
	bound := hostsOverlap(host, viper.GetString("domain"))

	state.HTTPListeners.Range(func(_ string, pH *HTTPHolder) bool {
		bound = bound || hostsOverlap(host, pH.HTTPUrl.Host)
		return !bound
	})

	return bound
}

// SNINameTaken reports whether binding name on tH would take connections from
// another binding. Only SNI load balancing shares a name, and overlapping
// wildcards are never shared, so the first binding keeps its names.
func SNINameTaken(state *State, tH *TCPHolder, name string) bool {
	taken := false

	tH.Balancers.Range(func(bound string, _ *roundrobin.RoundRobin) bool {
		if bound == name {
			taken = !viper.GetBool("sni-load-balancer")
		} else if bound != "" && hostsOverlap(name, bound) {
			taken = true
		}

		return !taken
	})

	// Raw TLS for an HTTP host would bypass sish's TLS for it.
	return taken || (tH.HTTPS && HTTPHostBound(state, name))
}

// GetOpenSNIHost returns an open SNI host or a random host if that one is unavailable.
func GetOpenSNIHost(addr string, state *State, sshConn *SSHConnection, tH *TCPHolder) (string, error) {
	getUnusedHost := func() (string, error) {
		first := true
		hostExtension := ""

		if viper.GetBool("append-user-to-subdomain") {
			hostExtension = viper.GetString("append-user-to-subdomain-separator") + sshConn.User()
		}

		var bindErr error

		dnsMatch, _, err := verifyDNS(addr, sshConn)
		if err != nil {
			slog.Debug(
				"error looking up txt records for host",
				"err", err,
				"host", addr,
			)
		}

		proposedHost := fmt.Sprintf("%s%s.%s", addr, hostExtension, viper.GetString("domain"))
		domainParts := strings.Join(strings.Split(addr, ".")[1:], ".")

		if dnsMatch || (viper.GetBool("bind-any-host") && strings.Contains(addr, ".")) || inList(domainParts, strings.FieldsFunc(viper.GetString("bind-hosts"), CommaSplitFields)) {
			proposedHost = addr

			if proposedHost == fmt.Sprintf(".%s", viper.GetString("domain")) {
				proposedHost = viper.GetString("domain")
			}
		}

		if viper.GetBool("bind-root-domain") && proposedHost == fmt.Sprintf(".%s", viper.GetString("domain")) {
			proposedHost = viper.GetString("domain")
		}

		host := strings.ToLower(proposedHost)

		getRandomHost := func() string {
			return strings.ToLower(RandomString(viper.GetInt("bind-random-subdomains-length")) + "." + viper.GetString("domain"))
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random subdomain."
				if viper.GetBool("force-requested-subdomains") {
					extra = ""
					bindErr = fmt.Errorf("unable to bind requested subdomain")
				}

				sshConn.SendLog(
					slog.LevelWarn,
					aurora.Sprintf("The subdomain %s is unavailable.%s", aurora.Red(host), extra),
					"subdomain unavailable",
					"subdomain", host,
					"assigningRandom", extra != "",
				)
			}
		}

		attempts := 0

		checkHost := func() bool {
			if bindErr != nil {
				return false
			}

			// A wildcard can cover every random name, so don't retry forever.
			attempts++
			if attempts > maxBindAttempts {
				bindErr = fmt.Errorf("unable to find a free subdomain")
				return false
			}

			if viper.GetBool("bind-random-subdomains") || !first || inList(host, bannedSubdomainList) || !validBindHost(host) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			if !viper.GetBool("bind-wildcards") && strings.HasPrefix(host, wildcardPrefix) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			ok := SNINameTaken(state, tH, host)

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkHost() {
		}

		return host, bindErr
	}

	return getUnusedHost()
}

// GetOpenHost returns an open host or a random host if that one is unavailable.
// If load balancing is enabled, it will return the requested domain.
func GetOpenHost(addr string, state *State, sshConn *SSHConnection) (*url.URL, *HTTPHolder) {
	getUnusedHost := func() (*url.URL, *HTTPHolder) {
		var pH *HTTPHolder

		first := true
		hostExtension := ""

		if viper.GetBool("append-user-to-subdomain") {
			hostExtension = viper.GetString("append-user-to-subdomain-separator") + sshConn.User()
		}

		var username string
		var password string
		var path string

		var bindErr error

		if strings.Contains(addr, "@") {
			hostParts := strings.SplitN(addr, "@", 2)

			addr = hostParts[1]

			if viper.GetBool("bind-http-auth") && len(hostParts[0]) > 0 {
				authParts := strings.Split(hostParts[0], ":")

				if len(authParts) > 0 {
					username = authParts[0]
				}

				if len(authParts) > 1 {
					password = authParts[1]
				}
			}
		}

		if strings.Contains(addr, "/") {
			pathParts := strings.SplitN(addr, "/", 2)

			if viper.GetBool("bind-http-path") && len(pathParts[1]) > 0 {
				path = fmt.Sprintf("/%s", pathParts[1])
			}

			addr = pathParts[0]
		}

		// These end up in URLs shown to users and admins, so a character that ends
		// the userinfo, host or path there could point the URL somewhere else.
		if !validURLPart(username, false) || !validURLPart(password, true) || !validURLPart(strings.ReplaceAll(path, "/", ""), true) {
			sshConn.SendLog(
				slog.LevelWarn,
				"The requested credentials or path contain characters that aren't allowed.\r\n",
				"invalid binding",
			)

			return nil, nil
		}

		dnsMatch, _, err := verifyDNS(addr, sshConn)
		if err != nil {
			slog.Debug(
				"error looking up txt records for host",
				"err", err,
				"host", addr,
			)
		}

		proposedHost := fmt.Sprintf("%s%s.%s", addr, hostExtension, viper.GetString("domain"))
		domainParts := strings.Join(strings.Split(addr, ".")[1:], ".")

		if dnsMatch || (viper.GetBool("bind-any-host") && strings.Contains(addr, ".")) || inList(domainParts, strings.FieldsFunc(viper.GetString("bind-hosts"), CommaSplitFields)) {
			proposedHost = addr

			if proposedHost == fmt.Sprintf(".%s", viper.GetString("domain")) {
				proposedHost = viper.GetString("domain")
			}
		}

		if viper.GetBool("bind-root-domain") && proposedHost == fmt.Sprintf(".%s", viper.GetString("domain")) {
			proposedHost = viper.GetString("domain")
		}

		host := strings.ToLower(proposedHost)

		getRandomHost := func() string {
			return strings.ToLower(RandomString(viper.GetInt("bind-random-subdomains-length")) + "." + viper.GetString("domain"))
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random subdomain."
				if viper.GetBool("force-requested-subdomains") {
					extra = ""
					bindErr = fmt.Errorf("unable to bind requested subdomain")
				}

				sshConn.SendLog(
					slog.LevelWarn,
					aurora.Sprintf("The subdomain %s is unavailable.%s", aurora.Red(host), extra),
					"subdomain unavailable",
					"subdomain", host,
					"assigningRandom", extra != "",
				)
			}
		}

		attempts := 0

		checkHost := func() bool {
			if bindErr != nil {
				return false
			}

			// A wildcard can cover every random name, so don't retry forever.
			attempts++
			if attempts > maxBindAttempts {
				bindErr = fmt.Errorf("unable to find a free subdomain")
				return false
			}

			if viper.GetBool("bind-random-subdomains") || !first || inList(host, bannedSubdomainList) || !validBindHost(host) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			if !viper.GetBool("bind-wildcards") && strings.HasPrefix(host, wildcardPrefix) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			holder, ok := httpBindingConflict(state, host, path, username, password)

			if holder != nil && viper.GetBool("http-load-balancer") {
				pH = holder
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkHost() {
		}

		if bindErr != nil {
			return nil, nil
		}

		hostUrl := &url.URL{
			User: url.UserPassword(username, password),
			Host: host,
			Path: path,
		}

		return hostUrl, pH
	}

	return getUnusedHost()
}

// GetOpenAlias returns open aliases or a random one if it is not enabled.
// If load balancing is enabled, it will return the requested alias.
func GetOpenAlias(addr string, port string, state *State, sshConn *SSHConnection) (string, *AliasHolder) {
	getUnusedAlias := func() (string, *AliasHolder) {
		var aH *AliasHolder
		var bindErr error

		first := true
		alias := fmt.Sprintf("%s:%s", strings.ToLower(addr), port)

		getRandomAlias := func() string {
			return fmt.Sprintf("%s:%s", strings.ToLower(RandomString(viper.GetInt("bind-random-aliases-length"))), port)
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random alias."
				if viper.GetBool("force-requested-aliases") {
					extra = ""

					bindErr = fmt.Errorf("unable to bind requested alias")
				}

				sshConn.SendLog(
					slog.LevelWarn,
					aurora.Sprintf("The alias %s is unavailable.%s", aurora.Red(alias), extra),
					"alias unavailable",
					"alias", alias,
					"assigningRandom", extra != "",
				)
			}
		}

		checkAlias := func() bool {
			if bindErr != nil {
				return false
			}

			if viper.GetBool("bind-random-aliases") || !first || inList(alias, bannedAliasList) {
				reportUnavailable(true)
				alias = getRandomAlias()
			}

			holder, ok := state.AliasListeners.Load(alias)
			if ok && viper.GetBool("alias-load-balancer") {
				aH = holder
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkAlias() {
		}

		if bindErr != nil {
			return "", nil
		}

		return alias, aH
	}

	return getUnusedAlias()
}

// RandomString returns a string of n letters and digits from crypto/rand.
func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	max := big.NewInt(int64(len(letters)))

	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			Fatal(
				"unable to read random bytes",
				"err", err,
			)
		}

		b[i] = letters[idx.Int64()]
	}

	return string(b)
}

// MatchHTTPHolder returns the listener for a request and whether the request
// still needs to send its credentials. An exact host beats a wildcard and the
// longest matching path wins. Listeners at the same host and path are told
// apart by the request's credentials.
func MatchHTTPHolder(listeners *syncmap.Map[string, *HTTPHolder], hostname, path, username, password string) (*HTTPHolder, bool) {
	type rank struct {
		exact            bool
		pathLen, hostLen int
	}

	rankOf := func(l *HTTPHolder) rank {
		return rank{exact: hostname == l.HTTPUrl.Host, pathLen: len(l.HTTPUrl.Path), hostLen: len(l.HTTPUrl.Host)}
	}

	better := func(a, b rank) bool {
		if a.exact != b.exact {
			return a.exact
		}

		if a.pathLen != b.pathLen {
			return a.pathLen > b.pathLen
		}

		return a.hostLen > b.hostLen
	}

	var best []*HTTPHolder
	var bestRank rank

	listeners.Range(func(_ string, l *HTTPHolder) bool {
		if !strings.HasPrefix(path, l.HTTPUrl.Path) || (hostname != l.HTTPUrl.Host && !MatchesWildcardHost(hostname, l.HTTPUrl.Host)) {
			return true
		}

		switch r := rankOf(l); {
		case len(best) == 0 || better(r, bestRank):
			best, bestRank = []*HTTPHolder{l}, r
		case r == bestRank:
			best = append(best, l)
		}

		return true
	})

	if len(best) == 0 {
		return nil, false
	}

	for _, l := range best {
		listenerUsername := l.HTTPUrl.User.Username()
		listenerPassword, _ := l.HTTPUrl.User.Password()

		if listenerUsername == "" || listenerPassword == "" {
			return l, false
		}

		// Both halves are compared so the time doesn't show which one was wrong.
		userMatches := TokenMatches(username, listenerUsername)
		passwordMatches := TokenMatches(password, listenerPassword)
		if userMatches && passwordMatches {
			return l, false
		}
	}

	return best[0], true
}

// TokenMatches compares a provided token with the expected one in constant time.
func TokenMatches(provided, expected string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// MatchesWildcardHost checks if the hostname provided would match the potential wildcard.
func MatchesWildcardHost(hostname string, potentialWildcard string) bool {
	if !strings.Contains(potentialWildcard, wildcardPrefix) {
		return false
	}

	return strings.HasPrefix(potentialWildcard, wildcardPrefix) && strings.HasSuffix(hostname, fmt.Sprintf(".%s", strings.TrimPrefix(potentialWildcard, wildcardPrefix)))
}
