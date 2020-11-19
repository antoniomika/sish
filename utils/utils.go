// Package utils implements utilities used across different
// areas of the sish application. There are utility functions
// that help with overall state management and are core to the application.
package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ScaleFT/sshkeys"
	"github.com/antoniomika/go-proxyproto"
	"github.com/fsnotify/fsnotify"
	"github.com/jpillora/ipfilter"
	"github.com/logrusorgru/aurora"
	"github.com/mikesmitty/edkey"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const (
	// sishDNSPrefix is the prefix used for DNS TXT records.
	sishDNSPrefix = "sish="
)

type SSHAuthKey struct {
	Key     ssh.PublicKey
	Options map[string][]string
	Comment string
}

var (
	// Filter is the IPFilter used to block connections.
	Filter *ipfilter.IPFilter

	// certHolder is a map of SSHAuthKey objects, the key is string(Key.key.Marshal()).
	certHolder = make(map[string]SSHAuthKey)

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
		l.UseTimeout = true
		l.Timeout = viper.GetDuration("proxy-protocol-timeout")

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
func GetRandomPortInRange(portRange string, authPorts []uint32) uint32 {
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

	mathrand.Seed(time.Now().UnixNano())

	if len(authPorts) > 0 {
		bindPort = authPorts[mathrand.Intn(len(authPorts))]
	} else {
		locHolder := mathrand.Intn(len(possible))

		if len(possible[locHolder]) == 1 {
			bindPort = uint32(possible[locHolder][0])
		} else if len(possible[locHolder]) == 2 {
			bindPort = uint32(mathrand.Intn(int(possible[locHolder][1]-possible[locHolder][0])) + int(possible[locHolder][0]))
		}

	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", bindPort))
	if err != nil {
		if len(authPorts) == 1 {
			return 0
		}
		if len(authPorts) > 1 {
			for i, p := range authPorts {
				if p == bindPort {
					authPorts = append(authPorts[:i], authPorts[i+1:]...)
					break
				}
			}
		}
		return GetRandomPortInRange(portRange, authPorts)
	}

	ln.Close()

	return bindPort
}

//Check if port is in provided slice.
func IsPortInSlice(p uint32, s []uint32) bool {

	for _, a := range s {
		if a == p {
			return true
		}
	}
	return false
}

// CheckPort verifies if a port exists within the port range.
// It will return 0 and an error if not (0 allows the kernel to select)
// the port.
func CheckPort(port uint32, portRanges string, authPorts []uint32) (uint32, error) {
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

	if len(authPorts) > 0 && !IsPortInSlice(port, authPorts) {
		checks = false
	}

	if checks {
		return port, nil
	}

	return 0, fmt.Errorf("not a safe port")
}

// WatchCerts watches ssh keys for changes and will load them.
func WatchCerts() {
	loadCerts()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for range c {
				watcher.Close()
				os.Exit(0)
			}
		}()

		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
				loadCerts()
			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()

	err = watcher.Add(viper.GetString("authentication-keys-directory"))
	if err != nil {
		log.Fatal(err)
	}
}

// parseSSHOptions parses options from ssh.ParseAuthorizedKey format to our map format for SSHAuthKey.
func parseSSHOptions(options []string) map[string][]string {
	ret := make(map[string][]string)
	for _, o := range options {
		values := make([]string, 0)
		optionSplit := strings.Split(o, "=")

		if len(optionSplit) == 1 {
			ret[optionSplit[0]] = values
		}
		if len(optionSplit) == 2 {
			v, ok := ret[optionSplit[0]]
			if ok {
				values = v
			}

			optionVal := optionSplit[1]
			if len(optionVal) > 0 && optionVal[0] == '"' {
				optionVal = optionVal[1:]
			}
			if len(optionVal) > 0 && optionVal[len(optionVal)-1] == '"' {
				optionVal = optionVal[:len(optionVal)-1]
			}

			values = append(values, optionVal)
			ret[optionSplit[0]] = values
		}

	}
	return ret
}

// loadCerts loads public keys from the keys directory into a slice that is used
// authenticating a user.
func loadCerts() {
	tmpCertHolder := make(map[string]SSHAuthKey)

	files, err := ioutil.ReadDir(viper.GetString("authentication-keys-directory"))
	if err != nil {
		log.Fatal(err)
	}

	parseKey := func(keyBytes []byte, fileInfo os.FileInfo) {
		keyHandle := func(keyBytes []byte, fileInfo os.FileInfo) []byte {
			key, comment, options, rest, e := ssh.ParseAuthorizedKey(keyBytes)
			if e != nil {
				log.Printf("Can't load file %s as public key: %s\n", fileInfo.Name(), e)
			}

			if key != nil {

				tmpCertHolder[string(key.Marshal())] = SSHAuthKey{
					key, parseSSHOptions(options), comment,
				}
			}
			return rest
		}

		for ok := true; ok; ok = len(keyBytes) > 0 {
			keyBytes = keyHandle(keyBytes, fileInfo)
		}
	}

	for _, f := range files {
		i, e := ioutil.ReadFile(filepath.Join(viper.GetString("authentication-keys-directory"), f.Name()))
		if e == nil && len(i) > 0 {
			parseKey(i, f)
		}
	}

	holderLock.Lock()
	defer holderLock.Unlock()
	certHolder = tmpCertHolder
}

// GetSSHConfig Returns an SSH config for the ssh muxer.
// It handles auth and storing user connection information.
func GetSSHConfig() *ssh.ServerConfig {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: !viper.GetBool("authentication"),
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Printf("Login attempt: %s, user %s", c.RemoteAddr(), c.User())

			if string(password) == viper.GetString("authentication-password") && viper.GetString("authentication-password") != "" {
				return nil, nil
			}

			return nil, fmt.Errorf("password doesn't match")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), string(ssh.MarshalAuthorizedKey(key)))

			holderLock.Lock()
			defer holderLock.Unlock()
			_, ok := certHolder[string(key.Marshal())]
			if ok {
				permssionsData := &ssh.Permissions{
					Extensions: map[string]string{
						"pubKey":            string(key.Marshal()),
						"pubKeyFingerprint": ssh.FingerprintSHA256(key),
					},
				}

				return permssionsData, nil
			}

			return nil, fmt.Errorf("public key doesn't match")
		},
	}
	sshConfig.AddHostKey(loadPrivateKey(viper.GetString("private-key-passphrase")))
	return sshConfig
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

	err = ioutil.WriteFile(viper.GetString("private-key-location"), pemData, 0600)
	if err != nil {
		log.Println("Error writing to file:", err)
	}

	return pemData
}

// ParsePrivateKey parses the PrivateKey into a ssh.Signer and
// let's it be used by the SSH server.
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := ioutil.ReadFile(viper.GetString("private-key-location"))
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

	records, err := net.LookupTXT(addr)

	for _, v := range records {
		if strings.HasPrefix(v, sishDNSPrefix) {
			dnsPubKeyFingerprint := strings.TrimSpace(strings.TrimPrefix(v, sishDNSPrefix))

			match := sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"] == dnsPubKeyFingerprint
			if match {
				return match, dnsPubKeyFingerprint, err
			}
		}
	}

	return false, "", nil
}

// GetOpenPort returns open ports that can be bound. It verifies the host to
// bind the port to and attempts to listen to the port to ensure it is open.
// If load balancing is enabled, it will return the port if used.
func GetOpenPort(addr string, port uint32, state *State, sshConn *SSHConnection) (string, uint32, *TCPHolder) {
	getUnusedPort := func() (string, uint32, *TCPHolder) {
		var tH *TCPHolder

		first := true
		bindPort := port
		bindAddr := addr
		listenAddr := ""
		authPorts := make([]uint32, 0)

		if bindAddr == "localhost" && viper.GetBool("localhost-as-all") {
			bindAddr = ""
		}

		getPortsFromAuthSettings := func() []uint32 {
			ret := make([]uint32, 0)
			holderLock.Lock()
			defer holderLock.Unlock()
			if sshConn.SSHConn.Permissions == nil {
				return ret
			}
			i, ok := certHolder[sshConn.SSHConn.Permissions.Extensions["pubKey"]]
			if !ok {
				return ret
			}
			ports, ok := i.Options["permitlisten"]
			if !ok {
				return ret
			}

			for _, p := range ports {
				authPortNum, err := strconv.ParseUint(p, 10, 32)
				if err != nil {
					log.Println("Invalid value in permitlisten option in authorized keys:", p)
					continue
				}
				ret = append(ret, uint32(authPortNum))
			}
			return ret
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				extra := " Assigning a random port."
				if viper.GetBool("force-requested-ports") {
					extra = ""
				}

				sshConn.SendMessage(aurora.Sprintf("The TCP port %s is unavailable.%s", aurora.Red(listenAddr), extra), true)
			}
		}

		checkPort := func(checkerAddr string, checkerPort uint32) bool {

			if viper.GetBool("use-ports-from-keys") {
				authPorts = getPortsFromAuthSettings()
				if len(authPorts) > 0 {
					if viper.GetBool("debug") {
						log.Println("The host has pre-assigned ports in auth keys:", authPorts)
					}
				}
			}

			listenAddr = fmt.Sprintf("%s:%d", bindAddr, bindPort)
			checkedPort, err := CheckPort(checkerPort, viper.GetString("port-bind-range"), authPorts)

			_, ok := state.TCPListeners.Load(listenAddr)

			if err == nil && (!viper.GetBool("tcp-load-balancer") || (viper.GetBool("tcp-load-balancer") && !ok)) {
				ln, listenErr := net.Listen("tcp", fmt.Sprintf(":%d", port))
				if listenErr != nil {
					err = listenErr
				} else {
					ln.Close()
				}
			}

			if viper.GetBool("bind-random-ports") || !first || err != nil {
				reportUnavailable(true)

				if viper.GetString("port-bind-range") != "" {
					bindPort = GetRandomPortInRange(viper.GetString("port-bind-range"), authPorts)
				} else {
					bindPort = 0
				}
			} else {
				bindPort = checkedPort
			}

			listenAddr = fmt.Sprintf("%s:%d", bindAddr, bindPort)
			holder, ok := state.TCPListeners.Load(listenAddr)
			if ok && viper.GetBool("tcp-load-balancer") {
				tH = holder.(*TCPHolder)
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkPort(bindAddr, bindPort) {
		}

		return listenAddr, bindPort, tH
	}

	return getUnusedPort()
}

// GetOpenHost returns an open host or a random host if that one is unavailable.
// If load balancing is enabled, it will return the requested domain.
func GetOpenHost(addr string, state *State, sshConn *SSHConnection) (string, *HTTPHolder) {
	dnsMatch, _, err := verifyDNS(addr, sshConn)
	if err != nil && viper.GetBool("debug") {
		log.Println("Error looking up txt records for domain:", addr)
	}

	getUnusedHost := func() (string, *HTTPHolder) {
		var pH *HTTPHolder

		first := true
		hostExtension := ""

		if viper.GetBool("append-user-to-subdomain") {
			hostExtension = viper.GetString("append-user-to-subdomain-separator") + sshConn.SSHConn.User()
		}

		proposedHost := addr + hostExtension + "." + viper.GetString("domain")
		domainParts := strings.Join(strings.Split(addr, ".")[1:], ".")

		if dnsMatch || (viper.GetBool("bind-any-host") && strings.Contains(addr, ".")) || inList(domainParts, strings.FieldsFunc(viper.GetString("bind-hosts"), CommaSplitFields)) {
			proposedHost = addr
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
				}

				sshConn.SendMessage(aurora.Sprintf("The subdomain %s is unavailable.%s", aurora.Red(host), extra), true)
			}
		}

		checkHost := func(checkHost string) bool {
			if viper.GetBool("bind-random-subdomains") || !first || inList(host, bannedSubdomainList) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			holder, ok := state.HTTPListeners.Load(host)
			if ok && viper.GetBool("http-load-balancer") {
				pH = holder.(*HTTPHolder)
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkHost(host) {
		}

		return host, pH
	}

	return getUnusedHost()
}

// GetOpenAlias returns open aliases or a random one if it is not enabled.
// If load balancing is enabled, it will return the requested alias.
func GetOpenAlias(addr string, port string, state *State, sshConn *SSHConnection) (string, *AliasHolder) {
	getUnusedAlias := func() (string, *AliasHolder) {
		var aH *AliasHolder

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
				}

				sshConn.SendMessage(aurora.Sprintf("The alias %s is unavailable.%s", aurora.Red(alias), extra), true)
			}
		}

		checkAlias := func(checkAlias string) bool {
			if viper.GetBool("bind-random-aliases") || !first || inList(alias, bannedAliasList) {
				reportUnavailable(true)
				alias = getRandomAlias()
			}

			holder, ok := state.AliasListeners.Load(alias)
			if ok && viper.GetBool("alias-load-balancer") {
				aH = holder.(*AliasHolder)
				ok = false
			}

			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkAlias(alias) {
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
