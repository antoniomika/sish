package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConnection handles state for a SSHConnection
type SSHConnection struct {
	SSHConn   *ssh.ServerConn
	Listeners *sync.Map
	Close     chan bool
	Messages  chan string
}

// State handles overall state
type State struct {
	SSHConnections *sync.Map
	Listeners      *sync.Map
	HTTPListeners  *sync.Map
}

var (
	serverAddr   = flag.String("sish.addr", "localhost:2222", "The address to listen for SSH connections")
	httpAddr     = flag.String("sish.http", "localhost:80", "The address to listen for HTTP connections")
	httpsAddr    = flag.String("sish.https", "localhost:443", "The address to listen for HTTPS connections")
	httpsEnabled = flag.Bool("sish.httpsenabled", false, "Whether or not to listen for HTTPS connections")
	httpsPems    = flag.String("sish.httpspems", "ssl/", "The location of pem files for HTTPS (fullchain.pem and privkey.pem)")
	rootDomain   = flag.String("sish.domain", "ssi.sh", "The domain for HTTP(S) multiplexing")
	domainLen    = flag.Int("sish.subdomainlen", 3, "The length of the random subdomain to generate")
	pkPass       = flag.String("sish.pkpass", "S3Cr3tP4$$phrAsE", "Passphrase to use for the server private key")
	pkLoc        = flag.String("sish.pkloc", "keys/ssh_key", "SSH server private key")
	authEnabled  = flag.Bool("sish.auth", false, "Whether or not to require auth on the SSH service")
	authPassword = flag.String("sish.password", "S3Cr3tP4$$W0rD", "Password to use for password auth")
	authKeysDir  = flag.String("sish.keysdir", "pubkeys/", "Directory for public keys for pubkey auth")
	bindRange    = flag.String("sish.bindrange", "0,1024-65535", "Ports that are allowed to be bound")
	bindRandom   = flag.Bool("sish.bindrandom", true, "Bind ports randomly (OS chooses)")
	debug        = flag.Bool("sish.debug", false, "Whether or not to print debug information")
)

func main() {
	flag.Parse()

	watchCerts()

	state := &State{
		SSHConnections: &sync.Map{},
		Listeners:      &sync.Map{},
		HTTPListeners:  &sync.Map{},
	}

	go startHTTPHandler(state)

	if *debug {
		go func() {
			for {
				log.Println("=======Start=========")
				log.Println("====Goroutines====")
				log.Println(runtime.NumGoroutine())
				log.Println("====Listeners=====")
				state.Listeners.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Println("====Clients=======")
				state.SSHConnections.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Print("========End==========\n\n")

				time.Sleep(2 * time.Second)
			}
		}()
	}

	log.Println("Starting SSH service on address:", *serverAddr)

	sshConfig := getSSHConfig()

	listener, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	state.Listeners.Store(listener.Addr(), listener)

	defer func() {
		listener.Close()
		state.Listeners.Delete(listener.Addr())
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			os.Exit(0)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		log.Println("Accepted SSH connection for:", conn.RemoteAddr())

		sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
		if err != nil {
			conn.Close()
			log.Println(err)
			continue
		}

		holderConn := &SSHConnection{
			SSHConn:   sshConn,
			Listeners: &sync.Map{},
			Close:     make(chan bool),
			Messages:  make(chan string),
		}

		state.SSHConnections.Store(sshConn.RemoteAddr(), holderConn)

		go handleRequests(reqs, holderConn, state)
		go handleChannels(chans, holderConn, state)
	}
}
