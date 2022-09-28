package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// MakeTestKeys returns a slice of randomly generated private keys.
func MakeTestKeys(numKeys int) []*rsa.PrivateKey {
	testKeys := make([]*rsa.PrivateKey, numKeys)
	for i := 0; i < numKeys; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		testKeys[i] = key
	}
	return testKeys
}

// PubKeyHttpHandler returns a http handler function which validates an
// OpenSSH authorized-keys formatted public key against a slice of
// slice authorized keys.
func PubKeyHttpHandler(validPublicKeys *[]rsa.PublicKey) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		pubKey, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		marshalled := parsedKey.Marshal()
		for _, key := range *validPublicKeys {
			authorizedKey, err := ssh.NewPublicKey(&key)
			if err != nil {
				log.Print("Error parsing authorized public key", err)
				continue
			}
			if bytes.Equal(authorizedKey.Marshal(), marshalled) {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// HandleSSHConn accepts an incoming client connection, performs the
// auth handshake to test the GetSSHConfig method using the
// authentication-key-request-url flag.
func HandleSSHConn(sshListener net.Listener, successAuth *chan bool) {
	conn, err := sshListener.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// GetSSHConfig is the method we are testing to validate that it
	// can use an http request to validate client public key auth
	connection, _, _, err := ssh.NewServerConn(conn, GetSSHConfig())

	if err != nil {
		*successAuth <- false
		return
	}
	connection.Close()

	*successAuth <- true
}

// TestAuthenticationKeyRequest validates that the utils.GetSSHConfig
// PublicKey auth works with the authentication-key-request-url parameter.
func TestAuthenticationKeyRequest(t *testing.T) {
	testKeys := MakeTestKeys(3)

	// Give sish a temp directory to generate a server ssh host key
	dir, err := os.MkdirTemp("", "sish_keys")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	viper.Set("private-keys-directory", dir)
	viper.Set("authentication", true)

	testCases := []struct {
		clientPrivateKey  *rsa.PrivateKey
		validPublicKeys   []rsa.PublicKey
		expectSuccessAuth bool
		overrideHttpUrl   string
	}{
		// valid key, should succeed auth
		{
			clientPrivateKey:  testKeys[0],
			validPublicKeys:   []rsa.PublicKey{testKeys[0].PublicKey},
			expectSuccessAuth: true,
			overrideHttpUrl:   "",
		},
		// invalid key, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			validPublicKeys:   []rsa.PublicKey{testKeys[1].PublicKey, testKeys[2].PublicKey},
			expectSuccessAuth: false,
			overrideHttpUrl:   "",
		},
		// no http service listening on server url, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			validPublicKeys:   []rsa.PublicKey{},
			expectSuccessAuth: false,
			overrideHttpUrl:   "http://localhost:61234",
		},
		// invalid http url, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			validPublicKeys:   []rsa.PublicKey{},
			expectSuccessAuth: false,
			overrideHttpUrl:   "notarealurl",
		},
	}

	for caseIdx, c := range testCases {
		if c.overrideHttpUrl == "" {
			// start an http server that will validate against the specified public keys
			httpSrv := httptest.NewServer(http.HandlerFunc(PubKeyHttpHandler(&c.validPublicKeys)))
			defer httpSrv.Close()

			// set viper to this http server URL as the auth request url it will
			// send public keys to for auth validation
			viper.Set("authentication-key-request-url", httpSrv.URL)
		} else {
			viper.Set("authentication-key-request-url", c.overrideHttpUrl)
		}

		sshListener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Error(err)
		}
		defer sshListener.Close()

		successAuth := make(chan bool)
		go HandleSSHConn(sshListener, &successAuth)

		// // attempt to connect to the ssh server using the specified private key
		signer, err := ssh.NewSignerFromKey(c.clientPrivateKey)
		if err != nil {
			t.Error(err)
		}
		clientConfig := &ssh.ClientConfig{
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		t.Log(clientConfig)

		client, err := ssh.Dial("tcp", sshListener.Addr().String(), clientConfig)
		if err != nil {
			t.Log("ssh client rejected", err)
		} else {
			t.Log("ssh client connected")
			client.Close()
		}

		didAuth := <-successAuth

		if didAuth != c.expectSuccessAuth {
			t.Errorf("Auth %t when should have been %t for case %d", didAuth, c.expectSuccessAuth, caseIdx)
		}
	}
}
