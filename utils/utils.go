package utils

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

	"github.com/fsnotify/fsnotify"
	"github.com/jpillora/ipfilter"
	"github.com/logrusorgru/aurora"
	"github.com/mikesmitty/edkey"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const (
	sishDNSPrefix = "sish="
)

var (
	// Filter is the IPFilter used to block connections
	Filter *ipfilter.IPFilter

	certHolder          = make([]ssh.PublicKey, 0)
	holderLock          = sync.Mutex{}
	bannedSubdomainList = []string{""}
)

// Setup main utils
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
}

// CommaSplitFields is a function used by strings.FieldsFunc to split around commas
func CommaSplitFields(c rune) bool {
	return c == ','
}

// GetRandomPortInRange returns a random port in the provided range
func GetRandomPortInRange(portRange string) uint32 {
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
	locHolder := mathrand.Intn(len(possible))

	if len(possible[locHolder]) == 1 {
		bindPort = uint32(possible[locHolder][0])
	} else if len(possible[locHolder]) == 2 {
		bindPort = uint32(mathrand.Intn(int(possible[locHolder][1]-possible[locHolder][0])) + int(possible[locHolder][0]))
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", bindPort))
	if err != nil {
		return GetRandomPortInRange(portRange)
	}

	ln.Close()

	return bindPort
}

// CheckPort verifies if a port exists within the port range
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

// WatchCerts watches ssh keys for changes
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

func loadCerts() {
	tmpCertHolder := make([]ssh.PublicKey, 0)

	files, err := ioutil.ReadDir(viper.GetString("authentication-keys-directory"))
	if err != nil {
		log.Fatal(err)
	}

	parseKey := func(keyBytes []byte, fileInfo os.FileInfo) {
		keyHandle := func(keyBytes []byte, fileInfo os.FileInfo) []byte {
			key, _, _, rest, e := ssh.ParseAuthorizedKey(keyBytes)
			if e != nil {
				log.Printf("Can't load file %s as public key: %s\n", fileInfo.Name(), e)
			}

			if key != nil {
				tmpCertHolder = append(tmpCertHolder, key)
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

// GetSSHConfig Returns an SSH config for the ssh muxer
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
			for _, i := range certHolder {
				if bytes.Equal(key.Marshal(), i.Marshal()) {
					permssionsData := &ssh.Permissions{
						Extensions: map[string]string{
							"pubKey":            string(key.Marshal()),
							"pubKeyFingerprint": ssh.FingerprintSHA256(key),
						},
					}

					return permssionsData, nil
				}
			}

			return nil, fmt.Errorf("public key doesn't match")
		},
	}
	sshConfig.AddHostKey(loadPrivateKey(viper.GetString("private-key-passphrase")))
	return sshConfig
}

func generatePrivateKey(passphrase string) []byte {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Generated RSA Keypair")

	pemBlock := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(pk),
	}

	var pemData []byte

	if passphrase != "" {
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			log.Fatal(err)
		}

		pemData = pem.EncodeToMemory(encBlock)
	} else {
		pemData = pem.EncodeToMemory(pemBlock)
	}

	err = ioutil.WriteFile(viper.GetString("private-key-location"), pemData, 0644)
	if err != nil {
		log.Println("Error writing to file:", err)
	}

	return pemData
}

// ParsePrivateKey pareses the PrivateKey into a ssh.Signer and let's it be used by CASigner
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := ioutil.ReadFile(viper.GetString("private-key-location"))
	if err != nil {
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

func inBannedList(host string, bannedList []string) bool {
	for _, v := range bannedList {
		if strings.TrimSpace(v) == host {
			return true
		}
	}

	return false
}

func verifyDNS(addr string, sshConn *SSHConnection) (bool, string, error) {
	if !viper.GetBool("verify-dns") || sshConn.SSHConn.Permissions == nil {
		return false, "", nil
	}

	if _, ok := sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"]; !ok {
		return false, "", nil
	}

	dnsPubKeyFingerprint := ""
	records, err := net.LookupTXT(addr)

	for _, v := range records {
		if strings.HasPrefix(v, sishDNSPrefix) {
			dnsPubKeyFingerprint = strings.TrimSpace(strings.TrimPrefix(v, sishDNSPrefix))
		}
	}

	return sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"] == dnsPubKeyFingerprint, dnsPubKeyFingerprint, err
}

// GetOpenPort returns open ports
func GetOpenPort(addr string, port uint32, state *State, sshConn *SSHConnection) (string, uint32, *TCPHolder) {
	getUnusedPort := func() (string, uint32, *TCPHolder) {
		var tH *TCPHolder

		first := true
		bindPort := port
		bindAddr := addr
		listenAddr := ""

		if bindAddr == "localhost" && viper.GetBool("localhost-as-all") {
			bindAddr = ""
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				sshConn.SendMessage(aurora.Sprintf("The TCP port %s is unavaible. Assigning a random port.", aurora.Red(listenAddr)), true)
			}
		}

		checkPort := func(checkerAddr string, checkerPort uint32) bool {
			listenAddr = fmt.Sprintf("%s:%d", bindAddr, bindPort)
			checkedPort, err := CheckPort(checkerPort, viper.GetString("port-bind-range"))
			if err == nil && !viper.GetBool("tcp-load-balancer") {
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
					bindPort = GetRandomPortInRange(viper.GetString("port-bind-range"))
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

// GetOpenHost returns a random open host
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
		if dnsMatch {
			proposedHost = addr
		}

		host := strings.ToLower(proposedHost)

		getRandomHost := func() string {
			return strings.ToLower(RandStringBytesMaskImprSrc(viper.GetInt("bind-random-subdomains-length")) + "." + viper.GetString("domain"))
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				sshConn.SendMessage(aurora.Sprintf("The subdomain %s is unavailable. Assigning a random subdomain.", aurora.Red(host)), true)
			}
		}

		checkHost := func(checkHost string) bool {
			if viper.GetBool("bind-random-subdomains") || !first || inBannedList(host, bannedSubdomainList) {
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

// GetOpenAlias returns open aliases
func GetOpenAlias(addr string, port string, state *State, sshConn *SSHConnection) (string, *AliasHolder) {
	getUnusedAlias := func() (string, *AliasHolder) {
		var aH *AliasHolder

		first := true
		alias := fmt.Sprintf("%s:%s", strings.ToLower(addr), port)

		getRandomAlias := func() string {
			return fmt.Sprintf("%s:%s", strings.ToLower(RandStringBytesMaskImprSrc(viper.GetInt("bind-random-subdomains-length"))), port)
		}

		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				sshConn.SendMessage(aurora.Sprintf("The alias %s is unavaible. Assigning a random alias.", aurora.Red(alias)), true)
			}
		}

		checkAlias := func(checkAlias string) bool {
			if viper.GetBool("bind-random-subdomains") || !first || inBannedList(alias, bannedSubdomainList) {
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
