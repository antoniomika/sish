// Package utils implements utilities used across different
// areas of the sish application. There are utility functions
// that help with overall state management and are core to the application.
package utils

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ScaleFT/sshkeys"
	"github.com/caddyserver/certmagic"
	"github.com/jpillora/ipfilter"
	"github.com/logrusorgru/aurora"
	"github.com/mikesmitty/edkey"
	"github.com/pires/go-proxyproto"
	"github.com/radovskyb/watcher"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
	"golang.org/x/crypto/ssh"
)

const (
	// sishDNSPrefix is the prefix used for DNS TXT records.
	sishDNSPrefix = "_sish"

	// Prefix used for defining wildcard host matchers.
	wildcardPrefix = "*."
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

	// multiWriter is the writer that can be used for writing to multiple locations.
	multiWriter io.Writer
)

// Setup main utils. This initializes, whitelists, blacklists,
// and log writers.
func Setup(logWriter io.Writer) {
	multiWriter = logWriter

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
}

// CommaSplitFields is a function used by strings.FieldsFunc to split around commas.
func CommaSplitFields(c rune) bool {
	return c == ','
}

// LoadProxyProtoConfig will load the timeouts and policies for the proxy protocol.
func LoadProxyProtoConfig(l *proxyproto.Listener) {
	if viper.GetBool("proxy-protocol-use-timeout") {
		l.ReadHeaderTimeout = viper.GetDuration("proxy-protocol-timeout")

		l.Policy = func(upstream net.Addr) (proxyproto.Policy, error) {
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
}

// GetRandomPortInRange returns a random port in the provided range.
// The port range is a comma separated list of ranges or ports.
func GetRandomPortInRange(listenAddr string, portRange string) uint32 {
	var bindPort uint32

	ranges := strings.Split(strings.TrimSpace(portRange), ",")
	possible := [][]uint64{}
	for _, r := range ranges {
		ends := strings.Split(strings.TrimSpace(r), "-")

		if len(ends) == 1 {
			ui, err := strconv.ParseUint(ends[0], 0, 64)
			if err != nil {
				return 0
			}

			possible = append(possible, []uint64{uint64(ui)})
		} else if len(ends) == 2 {
			ui1, err := strconv.ParseUint(ends[0], 0, 64)
			if err != nil {
				return 0
			}

			ui2, err := strconv.ParseUint(ends[1], 0, 64)
			if err != nil {
				return 0
			}

			possible = append(possible, []uint64{uint64(ui1), uint64(ui2)})
		}
	}

	locHolder := mathrand.Intn(len(possible))

	if len(possible[locHolder]) == 1 {
		bindPort = uint32(possible[locHolder][0])
	} else if len(possible[locHolder]) == 2 {
		bindPort = uint32(mathrand.Intn(int(possible[locHolder][1]-possible[locHolder][0])) + int(possible[locHolder][0]))
	}

	ln, err := Listen(GenerateAddress(listenAddr, bindPort))
	if err != nil {
		return GetRandomPortInRange(listenAddr, portRange)
	}

	ln.Close()

	return bindPort
}

// CheckPort verifies if a port exists within the port range.
// It will return 0 and an error if not (0 allows the kernel to select)
// the port.
func CheckPort(port uint32, portRanges string) (uint32, error) {
	ranges := strings.Split(strings.TrimSpace(portRanges), ",")
	checks := false
	for _, r := range ranges {
		ends := strings.Split(strings.TrimSpace(r), "-")

		if len(ends) == 1 {
			ui, err := strconv.ParseUint(ends[0], 0, 64)
			if err != nil {
				return 0, err
			}

			if uint64(ui) == uint64(port) {
				checks = true
				continue
			}
		} else if len(ends) == 2 {
			ui1, err := strconv.ParseUint(ends[0], 0, 64)
			if err != nil {
				return 0, err
			}

			ui2, err := strconv.ParseUint(ends[1], 0, 64)
			if err != nil {
				return 0, err
			}

			if uint64(port) >= ui1 && uint64(port) <= ui2 {
				checks = true
				continue
			}
		}
	}

	if checks {
		return port, nil
	}

	return 0, fmt.Errorf("not a safe port")
}

func loadCerts(certManager *certmagic.Config) {
	certFiles, err := filepath.Glob(filepath.Join(viper.GetString("https-certificate-directory"), "*.crt"))
	if err != nil {
		log.Println("Error loading unmanaged certificates:", err)
	}

	ctx := context.TODO()

	for _, v := range certFiles {
		_, err := certManager.CacheUnmanagedCertificatePEMFile(ctx, v, fmt.Sprintf("%s.key", strings.TrimSuffix(v, ".crt")), []string{})
		if err != nil {
			log.Println("Error loading unmanaged certificate:", err)
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
			log.Printf("Error parsing private key file %s: %s\n", directory.Name(), err)
			return
		}

		log.Printf("Loading %s as %s host key", directory.Name(), key.PublicKey().Type())

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
			log.Printf("Error walking file %s for private key: %s\n", d.Name(), err)
			return nil
		}

		i, e := os.ReadFile(path)
		if e != nil {
			log.Printf("Can't read file %s as private key: %s\n", d.Name(), err)
			return nil
		}

		if len(i) > 0 {
			parseKey(i, d)
		}

		return nil
	})

	if err != nil {
		log.Printf("Unable to walk private-keys-directory %s: %s\n", viper.GetString("private-keys-directory"), err)
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
		log.Fatalln(err)
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
			log.Fatalln(err)
		}
	}()
}

// WatchKeys watches ssh keys for changes and will load them.
func WatchKeys() {
	loadKeys()

	w := watcher.New()
	w.SetMaxEvents(1)

	if err := w.AddRecursive(viper.GetString("authentication-keys-directory")); err != nil {
		log.Fatalln(err)
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
			log.Fatalln(err)
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
					log.Printf("Can't load file %s:\"%s\" as public key: %s\n", d.Name(), string(keyBytes), e)
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
		if d.IsDir() {
			return nil
		}

		if err != nil {
			log.Printf("Error walking file %s for public key: %s\n", d.Name(), err)
			return nil
		}

		i, e := os.ReadFile(path)
		if e != nil {
			log.Printf("Can't read file %s as public key: %s\n", d.Name(), err)
			return nil
		}

		if len(i) > 0 {
			parseKey(i, d)
		}

		return nil
	})

	if err != nil {
		log.Printf("Unable to walk authentication-keys-directory %s: %s\n", viper.GetString("authentication-keys-directory"), err)
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
			log.Printf("Login attempt: %s, user %s", c.RemoteAddr(), c.User())

			if string(password) == viper.GetString("authentication-password") && viper.GetString("authentication-password") != "" {
				return nil, nil
			}

			// Allow validation of passwords via a sub-request to another service
			authUrl := viper.GetString("authentication-password-request-url")
			if authUrl != "" {
				validKey, err := checkAuthenticationPasswordRequest(authUrl, password, c.RemoteAddr(), c.User())
				if err != nil {
					log.Printf("Error calling authentication password URL %s: %s\n", authUrl, err)
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

			log.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), string(authKey))

			holderLock.Lock()
			defer holderLock.Unlock()
			for _, i := range certHolder {
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
					log.Printf("Error calling authentication key URL %s: %s\n", authUrl, err)
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

	c := &http.Client{
		Timeout: viper.GetDuration("authentication-key-request-timeout"),
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

	if res.StatusCode != http.StatusOK {
		log.Printf("Public key rejected by auth service: %s with status %d", urlS, res.StatusCode)
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

	c := &http.Client{
		Timeout: viper.GetDuration("authentication-password-request-timeout"),
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

	if res.StatusCode != http.StatusOK {
		log.Printf("Password rejected by auth service: %s with status %d", urlS, res.StatusCode)
		return false, nil
	}

	return true, nil
}

// generatePrivateKey creates a new ed25519 private key to be used by the
// the SSH server as the host key.
func generatePrivateKey(passphrase string) []byte {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Generated ED25519 Keypair")

	// In an effort to guarantee that keys can still be loaded by OpenSSH
	// we adopt branching logic here for passphrase encrypted keys.
	// I wrote a module that handled both, but ultimately decided this
	// is likely cleaner and less specialized.
	var pemData []byte
	if passphrase != "" {
		pemData, err = sshkeys.Marshal(pk, &sshkeys.MarshalOptions{
			Passphrase: []byte(passphrase),
			Format:     sshkeys.FormatOpenSSHv1,
		})

		if err != nil {
			log.Fatal(err)
		}
	} else {
		pemBlock := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(pk),
		}

		pemData = pem.EncodeToMemory(pemBlock)
	}

	err = os.WriteFile(filepath.Join(viper.GetString("private-keys-directory"), "ssh_key"), pemData, 0600)
	if err != nil {
		log.Println("Error writing to file:", err)
	}

	return pemData
}

// ParsePrivateKey parses the PrivateKey into a ssh.Signer and
// let's it be used by the SSH server.
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := os.ReadFile(filepath.Join(viper.GetString("private-keys-directory"), "ssh_key"))
	if err != nil {
		log.Println("Error loading private key, generating a new one:", err)
		pk = generatePrivateKey(passphrase)
	}

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pk, []byte(passphrase))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pk)
		if err != nil {
			log.Fatal(err)
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

	records, err := net.LookupTXT(fmt.Sprintf("%s.%s", sishDNSPrefix, addr))

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
func GetOpenPort(addr string, port uint32, state *State, sshConn *SSHConnection, sniProxyEnabled bool) (string, uint32, *TCPHolder) {
	getUnusedPort := func() (string, uint32, *TCPHolder) {
		var tH *TCPHolder
		var bindErr error

		first := true
		bindPort := port
		bindAddr := addr
		listenAddr := ""

		if bindAddr == "" {
			bindAddr = sshConn.TCPAddress
		}

		if (bindAddr == "localhost" && viper.GetBool("localhost-as-all")) || viper.GetBool("force-tcp-address") || (sniProxyEnabled && sshConn.TCPAddress == "") {
			bindAddr = viper.GetString("tcp-address")
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random port."
				if viper.GetBool("force-requested-ports") {
					extra = ""

					bindErr = fmt.Errorf("unable to bind requested port")
				}

				sshConn.SendMessage(aurora.Sprintf("The TCP port %d is unavailable.%s", aurora.Red(bindPort), extra), true)
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
					ln.Close()
				}
			}

			if viper.GetBool("bind-random-ports") || !first || err != nil {
				reportUnavailable(true)

				if viper.GetString("port-bind-range") != "" {
					bindPort = GetRandomPortInRange(bindAddr, viper.GetString("port-bind-range"))
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

		return listenAddr, bindPort, tH
	}

	return getUnusedPort()
}

// GetOpenSNIHost returns an open SNI host or a random host if that one is unavailable.
func GetOpenSNIHost(addr string, state *State, sshConn *SSHConnection, tH *TCPHolder) (string, error) {
	getUnusedHost := func() (string, error) {
		first := true
		hostExtension := ""

		if viper.GetBool("append-user-to-subdomain") {
			hostExtension = viper.GetString("append-user-to-subdomain-separator") + sshConn.SSHConn.User()
		}

		var bindErr error

		dnsMatch, _, err := verifyDNS(addr, sshConn)
		if err != nil && viper.GetBool("debug") {
			log.Println("Error looking up txt records for domain:", addr)
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
			return strings.ToLower(RandStringBytesMaskImprSrc(viper.GetInt("bind-random-subdomains-length")) + "." + viper.GetString("domain"))
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random subdomain."
				if viper.GetBool("force-requested-subdomains") {
					extra = ""
					bindErr = fmt.Errorf("unable to bind requested subdomain")
				}

				sshConn.SendMessage(aurora.Sprintf("The subdomain %s is unavailable.%s", aurora.Red(host), extra), true)
			}
		}

		checkHost := func() bool {
			if bindErr != nil {
				return false
			}

			if viper.GetBool("bind-random-subdomains") || !first || inList(host, bannedSubdomainList) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			if !viper.GetBool("bind-wildcards") && strings.HasPrefix(host, wildcardPrefix) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			ok := false

			tH.Balancers.Range(func(strKey string, value *roundrobin.RoundRobin) bool {
				if strKey == host {
					ok = true
					return false
				}

				return true
			})

			if ok && viper.GetBool("sni-load-balancer") {
				ok = false
			}

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
			hostExtension = viper.GetString("append-user-to-subdomain-separator") + sshConn.SSHConn.User()
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

		dnsMatch, _, err := verifyDNS(addr, sshConn)
		if err != nil && viper.GetBool("debug") {
			log.Println("Error looking up txt records for domain:", addr)
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
			return strings.ToLower(RandStringBytesMaskImprSrc(viper.GetInt("bind-random-subdomains-length")) + "." + viper.GetString("domain"))
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random subdomain."
				if viper.GetBool("force-requested-subdomains") {
					extra = ""
					bindErr = fmt.Errorf("unable to bind requested subdomain")
				}

				sshConn.SendMessage(aurora.Sprintf("The subdomain %s is unavailable.%s", aurora.Red(host), extra), true)
			}
		}

		checkHost := func() bool {
			if bindErr != nil {
				return false
			}

			if viper.GetBool("bind-random-subdomains") || !first || inList(host, bannedSubdomainList) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			if !viper.GetBool("bind-wildcards") && strings.HasPrefix(host, wildcardPrefix) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			var holder *HTTPHolder
			ok := false

			state.HTTPListeners.Range(func(key string, locationListener *HTTPHolder) bool {
				parsedPassword, _ := locationListener.HTTPUrl.User.Password()

				if host == locationListener.HTTPUrl.Host && strings.HasPrefix(path, locationListener.HTTPUrl.Path) && username == locationListener.HTTPUrl.User.Username() && password == parsedPassword {
					ok = true
					holder = locationListener
					return false
				}

				return true
			})

			if ok && viper.GetBool("http-load-balancer") {
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
			return fmt.Sprintf("%s:%s", strings.ToLower(RandStringBytesMaskImprSrc(viper.GetInt("bind-random-aliases-length"))), port)
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random alias."
				if viper.GetBool("force-requested-aliases") {
					extra = ""

					bindErr = fmt.Errorf("unable to bind requested alias")
				}

				sshConn.SendMessage(aurora.Sprintf("The alias %s is unavailable.%s", aurora.Red(alias), extra), true)
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

// RandStringBytesMaskImprSrc creates a random string of length n
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func RandStringBytesMaskImprSrc(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	var src = mathrand.NewSource(time.Now().UnixNano())

	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// MatchesWildcardHost checks if the hostname provided would match the potential wildcard.
func MatchesWildcardHost(hostname string, potentialWildcard string) bool {
	if !strings.Contains(potentialWildcard, wildcardPrefix) {
		return false
	}

	return strings.HasPrefix(potentialWildcard, wildcardPrefix) && strings.HasSuffix(hostname, fmt.Sprintf(".%s", strings.TrimPrefix(potentialWildcard, wildcardPrefix)))
}
