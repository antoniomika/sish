package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/ipfilter"

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
	IPFilter       *ipfilter.IPFilter
}

var (
	serverAddr           = flag.String("sish.addr", "localhost:2222", "The address to listen for SSH connections")
	httpAddr             = flag.String("sish.http", "localhost:80", "The address to listen for HTTP connections")
	httpsAddr            = flag.String("sish.https", "localhost:443", "The address to listen for HTTPS connections")
	verifySSL            = flag.Bool("sish.verifyssl", true, "Whether or not to verify SSL on proxy connection")
	httpsEnabled         = flag.Bool("sish.httpsenabled", false, "Whether or not to listen for HTTPS connections")
	redirectRoot         = flag.Bool("sish.redirectroot", true, "Whether or not to redirect the root domain")
	redirectRootLocation = flag.String("sish.redirectrootlocation", "https://github.com/antoniomika/sish", "Where to redirect the root domain to")
	httpsPems            = flag.String("sish.httpspems", "ssl/", "The location of pem files for HTTPS (fullchain.pem and privkey.pem)")
	rootDomain           = flag.String("sish.domain", "ssi.sh", "The domain for HTTP(S) multiplexing")
	domainLen            = flag.Int("sish.subdomainlen", 3, "The length of the random subdomain to generate")
	forceRandomSubdomain = flag.Bool("sish.forcerandomsubdomain", true, "Whether or not to force a random subdomain")
	bannedSubdomains     = flag.String("sish.bannedsubdomains", "localhost", "A comma separated list of banned subdomains")
	bannedIPs            = flag.String("sish.bannedips", "", "A comma separated list of banned ips")
	bannedCountries      = flag.String("sish.bannedcountries", "", "A comma separated list of banned countries")
	whitelistedIPs       = flag.String("sish.whitelistedips", "", "A comma separated list of whitelisted ips")
	whitelistedCountries = flag.String("sish.whitelistedcountries", "", "A comma separated list of whitelisted countries")
	useGeoDB             = flag.Bool("sish.usegeodb", false, "Whether or not to use the maxmind geodb")
	pkPass               = flag.String("sish.pkpass", "S3Cr3tP4$$phrAsE", "Passphrase to use for the server private key")
	pkLoc                = flag.String("sish.pkloc", "keys/ssh_key", "SSH server private key")
	authEnabled          = flag.Bool("sish.auth", false, "Whether or not to require auth on the SSH service")
	authPassword         = flag.String("sish.password", "S3Cr3tP4$$W0rD", "Password to use for password auth")
	authKeysDir          = flag.String("sish.keysdir", "pubkeys/", "Directory for public keys for pubkey auth")
	bindRange            = flag.String("sish.bindrange", "0,1024-65535", "Ports that are allowed to be bound")
	cleanupUnbound       = flag.Bool("sish.cleanupunbound", true, "Whether or not to cleanup unbound (forwarded) SSH connections")
	bindRandom           = flag.Bool("sish.bindrandom", true, "Bind ports randomly (OS chooses)")
	debug                = flag.Bool("sish.debug", false, "Whether or not to print debug information")
	bannedSubdomainList  = []string{""}
	filter               ipfilter.IPFilter
)

func main() {
	flag.Parse()

	commaSplitFields := func(c rune) bool {
		return c == ','
	}

	bannedSubdomainList = append(bannedSubdomainList, strings.FieldsFunc(*bannedSubdomains, commaSplitFields)...)
	for k, v := range bannedSubdomainList {
		bannedSubdomainList[k] = strings.ToLower(strings.TrimSpace(v) + "." + *rootDomain)
	}

	upperList := func(stringList string) []string {
		list := strings.FieldsFunc(stringList, commaSplitFields)
		for k, v := range list {
			list[k] = strings.ToUpper(v)
		}

		return list
	}

	whitelistedCountriesList := upperList(*whitelistedCountries)
	whitelistedIPList := strings.FieldsFunc(*whitelistedIPs, commaSplitFields)

	ipfilterOpts := ipfilter.Options{
		BlockedCountries: upperList(*bannedCountries),
		AllowedCountries: whitelistedCountriesList,
		BlockedIPs:       strings.FieldsFunc(*bannedIPs, commaSplitFields),
		AllowedIPs:       whitelistedIPList,
		BlockByDefault:   len(whitelistedIPList) > 0 || len(whitelistedCountriesList) > 0,
	}

	var filter *ipfilter.IPFilter

	if *useGeoDB {
		filter = ipfilter.NewLazy(ipfilterOpts)
	} else {
		filter = ipfilter.NewNoDB(ipfilterOpts)
	}

	watchCerts()

	state := &State{
		SSHConnections: &sync.Map{},
		Listeners:      &sync.Map{},
		HTTPListeners:  &sync.Map{},
		IPFilter:       filter,
	}

	go startHTTPHandler(state)

	if *debug {
		go func() {
			for {
				log.Println("=======Start=========")
				log.Println("===Goroutines=====")
				log.Println(runtime.NumGoroutine())
				log.Println("===Listeners======")
				state.Listeners.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Println("===Clients========")
				state.SSHConnections.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Println("===HTTP Clients===")
				state.HTTPListeners.Range(func(key, value interface{}) bool {
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

		clientRemote, _, err := net.SplitHostPort(conn.RemoteAddr().String())

		if err != nil || filter.Blocked(clientRemote) {
			conn.Close()
			continue
		}

		log.Println("Accepted SSH connection for:", conn.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			if err != nil {
				conn.Close()
				log.Println(err)
				return
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

			if *cleanupUnbound {
				go func() {
					select {
					case <-time.NewTimer(1 * time.Second).C:
						count := 0
						holderConn.Listeners.Range(func(key, value interface{}) bool {
							count++
							return true
						})

						if count == 0 {
							holderConn.Messages <- "No forwarding requests sent. Closing connection."
							time.Sleep(1 * time.Millisecond)
							holderConn.CleanUp(state)
						}
					case <-holderConn.Close:
						return
					}
				}()
			}
		}()
	}
}

// CleanUp closes all allocated resources and cleans them up
func (s *SSHConnection) CleanUp(state *State) {
	close(s.Close)
	close(s.Messages)
	s.SSHConn.Close()
	state.SSHConnections.Delete(s.SSHConn.RemoteAddr())
	log.Println("Closed SSH connection for:", s.SSHConn.RemoteAddr(), "user:", s.SSHConn.User())
}
