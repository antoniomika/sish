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
	serverAddr = flag.String("sish.addr", "localhost:8080", "The address to listen for SSH connections")
	httpAddr   = flag.String("sish.http", "localhost:8081", "The address to listen for HTTP connections")
	httpsAddr  = flag.String("sish.https", "localhost:8082", "The address to listen for HTTPS connections")
	rootDomain = flag.String("sish.domain", "foobar.mik.qa", "The address to listen for HTTPS connections")
	debug      = flag.Bool("sish.debug", true, "Whether or not to print debug information")
)

func main() {
	flag.Parse()

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
		log.Println(err)
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
