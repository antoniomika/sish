package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"
)

var (
	certHolder = make([]ssh.PublicKey, 0)
	holderLock = sync.Mutex{}
)

func checkPort(port uint32, portRanges string) (uint32, error) {
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
		}

		if len(ends) == 2 {
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

func watchCerts() {
	loadCerts()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill)
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

	err = watcher.Add(*authKeysDir)
	if err != nil {
		log.Fatal(err)
	}
}

func loadCerts() {
	tmpCertHolder := make([]ssh.PublicKey, 0)

	files, err := ioutil.ReadDir(*authKeysDir)
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
		rest := keyHandle(keyBytes, fileInfo)

		if len(rest) > 0 {
			keyHandle(rest, fileInfo)
		}
	}

	for _, f := range files {
		i, e := ioutil.ReadFile(filepath.Join(*authKeysDir, f.Name()))
		if e == nil && len(i) > 0 {
			parseKey(i, f)
		}
	}

	holderLock.Lock()
	defer holderLock.Unlock()
	certHolder = tmpCertHolder
}

func getSSHConfig() *ssh.ServerConfig {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: !*authEnabled,
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Printf("Login attempt: %s, user %s", c.RemoteAddr(), c.User())

			if string(password) == *authPassword && *authPassword != "" {
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
					return nil, nil
				}
			}

			return nil, fmt.Errorf("public key doesn't match")
		},
	}
	sshConfig.AddHostKey(loadPrivateKey(*pkPass))
	return sshConfig
}

func generatePrivateKey(passphrase string) []byte {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Generated RSA Keypair")

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
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

	ioutil.WriteFile(*pkLoc, pemData, 0644)

	return pemData
}

// ParsePrivateKey pareses the PrivateKey into a ssh.Signer and let's it be used by CASigner
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := ioutil.ReadFile(*pkLoc)
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

func getOpenHost(addr string, state *State, sshConn *SSHConnection) string {
	getUnusedHost := func() string {
		first := true
		host := strings.ToLower(addr + "." + *rootDomain)
		getRandomHost := func() string {
			return strings.ToLower(RandStringBytesMaskImprSrc(*domainLen) + "." + *rootDomain)
		}
		reportUnavailable := func(unavailable bool) {
			if first && unavailable {
				sshConn.Messages <- "This subdomain is unavaible. Assigning a random subdomain."
			}
		}

		checkHost := func(checkHost string) bool {
			if *forceRandomSubdomain || !first || inBannedList(host, bannedSubdomainList) {
				reportUnavailable(true)
				host = getRandomHost()
			}

			_, ok := state.HTTPListeners.Load(host)
			reportUnavailable(ok)

			first = false
			return ok
		}

		for checkHost(host) {
		}

		return host
	}

	return getUnusedHost()
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
