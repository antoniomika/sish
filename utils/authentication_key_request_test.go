package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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

type AuthRequestBody struct {
	PubKey     string `json:"auth_key"`
	UserName   string `json:"user"`
	RemoteAddr string `json:"remote_addr"`
}

// PubKeyHttpHandler returns a http handler function which validates an
// OpenSSH authorized-keys formatted public key against a slice of
// slice authorized keys.
func PubKeyHttpHandler(validPublicKeys *[]rsa.PublicKey, validUsernames *[]string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		pubKey, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var reqBody AuthRequestBody
		err = json.Unmarshal(pubKey, &reqBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(reqBody.PubKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		marshalled := parsedKey.Marshal()
		keyMatch := false
		usernameMatch := false
		for _, key := range *validPublicKeys {
			authorizedKey, err := ssh.NewPublicKey(&key)
			if err != nil {
				log.Print("Error parsing authorized public key", err)
				continue
			}
			if bytes.Equal(authorizedKey.Marshal(), marshalled) {
				keyMatch = true
				break
			}
		}
		for _, username := range *validUsernames {
			if reqBody.UserName == username {
				usernameMatch = true
			}
		}
		if keyMatch && usernameMatch {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
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

	defer func() {
		err := conn.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
		}
	}()

	// GetSSHConfig is the method we are testing to validate that it
	// can use an http request to validate client public key auth
	connection, _, _, err := ssh.NewServerConn(conn, GetSSHConfig())

	if err != nil {
		*successAuth <- false
		return
	}

	err = connection.Close()
	if err != nil {
		log.Print("Error closing connection", err)
	}

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

	defer func() {
		err := os.RemoveAll(dir)
		if err != nil {
			t.Error(err)
		}
	}()

	viper.Set("private-keys-directory", dir)
	viper.Set("authentication", true)

	testCases := []struct {
		clientPrivateKey  *rsa.PrivateKey
		clientUser        string
		validPublicKeys   []rsa.PublicKey
		validUsernames    []string
		expectSuccessAuth bool
		overrideHttpUrl   string
	}{
		// valid key, should succeed auth
		{
			clientPrivateKey:  testKeys[0],
			clientUser:        "ubuntu",
			validPublicKeys:   []rsa.PublicKey{testKeys[0].PublicKey},
			validUsernames:    []string{"ubuntu"},
			expectSuccessAuth: true,
			overrideHttpUrl:   "",
		},
		// invalid key, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			clientUser:        "ubuntu",
			validPublicKeys:   []rsa.PublicKey{testKeys[1].PublicKey, testKeys[2].PublicKey},
			validUsernames:    []string{"ubuntu"},
			expectSuccessAuth: false,
			overrideHttpUrl:   "",
		},
		// invalid username, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			clientUser:        "windows",
			validPublicKeys:   []rsa.PublicKey{testKeys[0].PublicKey},
			validUsernames:    []string{"ubuntu"},
			expectSuccessAuth: false,
			overrideHttpUrl:   "",
		},
		// no http service listening on server url, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			clientUser:        "ubuntu",
			validPublicKeys:   []rsa.PublicKey{testKeys[0].PublicKey},
			validUsernames:    []string{"ubuntu"},
			expectSuccessAuth: false,
			overrideHttpUrl:   "http://localhost:61234",
		},
		// invalid http url, should be rejected
		{
			clientPrivateKey:  testKeys[0],
			clientUser:        "ubuntu",
			validPublicKeys:   []rsa.PublicKey{testKeys[0].PublicKey},
			validUsernames:    []string{"ubuntu"},
			expectSuccessAuth: false,
			overrideHttpUrl:   "notarealurl",
		},
	}

	for caseIdx, c := range testCases {
		if c.overrideHttpUrl == "" {
			// start an http server that will validate against the specified public keys
			httpSrv := httptest.NewServer(http.HandlerFunc(PubKeyHttpHandler(&c.validPublicKeys, &c.validUsernames)))
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
		defer func() {
			err := sshListener.Close()
			if err != nil {
				t.Error(err)
			}
		}()

		successAuth := make(chan bool)
		go HandleSSHConn(sshListener, &successAuth)

		// attempt to connect to the ssh server using the specified private key
		signer, err := ssh.NewSignerFromKey(c.clientPrivateKey)
		if err != nil {
			t.Error(err)
		}
		clientConfig := &ssh.ClientConfig{
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			User:            c.clientUser,
		}
		t.Log(clientConfig)

		client, err := ssh.Dial("tcp", sshListener.Addr().String(), clientConfig)
		if err != nil {
			t.Log("ssh client rejected", err)
		} else {
			t.Log("ssh client connected")
			err := client.Close()
			if err != nil {
				t.Log("Error closing", err)
			}
		}

		didAuth := <-successAuth

		if didAuth != c.expectSuccessAuth {
			t.Errorf("Auth %t when should have been %t for case %d", didAuth, c.expectSuccessAuth, caseIdx)
		}
	}
}
