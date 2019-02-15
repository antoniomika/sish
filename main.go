package main

import (
	"flag"
	"fmt"
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
)

func main() {
	state := &State{
		SSHConnections: &sync.Map{},
		Listeners:      &sync.Map{},
		HTTPListeners:  &sync.Map{},
	}

	go startHTTPHandler(state)

	go func() {
		for {
			fmt.Println("=======Start=========")
			fmt.Println("====Goroutines====")
			fmt.Println(runtime.NumGoroutine())
			fmt.Println("====Listeners=====")
			state.Listeners.Range(func(key, value interface{}) bool {
				fmt.Println(key, value)
				return true
			})
			fmt.Println("====Clients=======")
			state.SSHConnections.Range(func(key, value interface{}) bool {
				fmt.Println(key, value)
				return true
			})
			fmt.Print("========End==========\n\n")

			time.Sleep(2 * time.Second)
		}
	}()

	fmt.Println("Starting service")

	sshConfig := getSSHConfig()

	listener, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		fmt.Println(err)
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
			fmt.Println(err)
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
		if err != nil {
			fmt.Println(err)
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
