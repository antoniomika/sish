package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"io/ioutil"
	mathrand "math/rand"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshKey = "keys/ssh_key"

func getSSHConfig() *ssh.ServerConfig {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			certcheck := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					return bytes.Equal(auth.Marshal(), []byte{})
				},
			}

			perms, err := certcheck.Authenticate(c, key)
			if err != nil {
				log.Println("Unable to verify certificate:", err)

				if err.Error() == "ssh: normal key pairs not accepted" {
					return nil, err
				}

				return nil, nil
			}

			return perms, nil
		},
	}
	sshConfig.AddHostKey(loadPrivateKey("foobar"))
	return sshConfig
}

func generatePrivateKey(passphrase string) []byte {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println(err)
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
			log.Println(err)
		}

		pemData = pem.EncodeToMemory(encBlock)
	} else {
		pemData = pem.EncodeToMemory(pemBlock)
	}

	ioutil.WriteFile(sshKey, pemData, 0644)

	return pemData
}

// ParsePrivateKey pareses the PrivateKey into a ssh.Signer and let's it be used by CASigner
func loadPrivateKey(passphrase string) ssh.Signer {
	var signer ssh.Signer

	pk, err := ioutil.ReadFile(sshKey)
	if err != nil {
		pk = generatePrivateKey(passphrase)
	}

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pk, []byte(passphrase))
		if err != nil {
			log.Println(err)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pk)
		if err != nil {
			log.Println(err)
		}
	}

	return signer
}

// RandStringBytesMaskImprSrc creates a random string of length n
func RandStringBytesMaskImprSrc(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
