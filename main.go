package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/ipfilter"

	"golang.org/x/crypto/ssh"
)

// SSHConnection handles state for a SSHConnection
type SSHConnection struct {
	SSHConn        *ssh.ServerConn
	Listeners      *sync.Map
	Close          chan bool
	Messages       chan string
	ProxyProto     byte
	Session        chan bool
	CleanupHandler bool
}

// State handles overall state
type State struct {
	SSHConnections *sync.Map
	Listeners      *sync.Map
	HTTPListeners  *sync.Map
	TCPListeners   *sync.Map
	IPFilter       *ipfilter.IPFilter
}

var (
	version              = "dev"
	commit               = "none"
	date                 = "unknown"
	httpPort             int
	httpsPort            int
	serverAddr           = flag.String("sish.addr", "localhost:2222", "The address to listen for SSH connections")
	httpAddr             = flag.String("sish.http", "localhost:80", "The address to listen for HTTP connections")
	httpPortOverride     = flag.Int("sish.httpport", 0, "The port to use for http command output")
	httpsAddr            = flag.String("sish.https", "localhost:443", "The address to listen for HTTPS connections")
	httpsPortOverride    = flag.Int("sish.httpsport", 0, "The port to use for https command output")
	verifyOrigin         = flag.Bool("sish.verifyorigin", true, "Whether or not to verify origin on websocket connection")
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
	proxyProtoEnabled    = flag.Bool("sish.proxyprotoenabled", false, "Whether or not to enable the use of the proxy protocol")
	proxyProtoVersion    = flag.String("sish.proxyprotoversion", "1", "What version of the proxy protocol to use. Can either be 1, 2, or userdefined. If userdefined, the user needs to add a command to SSH called proxyproto:version (ie proxyproto:1)")
	debug                = flag.Bool("sish.debug", false, "Whether or not to print debug information")
	versionCheck         = flag.Bool("sish.version", false, "Print version and exit")
	tcpAlias             = flag.Bool("sish.tcpalias", false, "Whether or not to allow the use of TCP aliasing")
	logToClient          = flag.Bool("sish.logtoclient", false, "Whether or not to log http requests to the client")
	idleTimeout          = flag.Int("sish.idletimeout", 5, "Number of seconds to wait for activity before closing a connection")
	bannedSubdomainList  = []string{""}
	filter               *ipfilter.IPFilter
)

func main() {
	flag.Parse()

	_, httpPortString, err := net.SplitHostPort(*httpAddr)
	if err != nil {
		log.Fatalln("Error parsing address:", err)
	}

	_, httpsPortString, err := net.SplitHostPort(*httpsAddr)
	if err != nil {
		log.Fatalln("Error parsing address:", err)
	}

	httpPort, err = strconv.Atoi(httpPortString)
	if err != nil {
		log.Fatalln("Error parsing address:", err)
	}

	httpsPort, err = strconv.Atoi(httpsPortString)
	if err != nil {
		log.Fatalln("Error parsing address:", err)
	}

	if *httpPortOverride != 0 {
		httpPort = *httpPortOverride
	}

	if *httpsPortOverride != 0 {
		httpsPort = *httpsPortOverride
	}

	if *versionCheck {
		log.Printf("\nVersion: %v\nCommit: %v\nDate: %v\n", version, commit, date)
		os.Exit(0)
	}

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
		TCPListeners:   &sync.Map{},
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
				log.Println("===TCP Aliases====")
				state.TCPListeners.Range(func(key, value interface{}) bool {
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
	signal.Notify(c, os.Interrupt)
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

		clientLoggedIn := false

		if *cleanupUnbound {
			go func() {
				<-time.After(5 * time.Second)
				if !clientLoggedIn {
					conn.Close()
				}
			}()
		}

		log.Println("Accepted SSH connection for:", conn.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			clientLoggedIn = true
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
				Session:   make(chan bool),
			}

			state.SSHConnections.Store(sshConn.RemoteAddr(), holderConn)

			go func() {
				err := sshConn.Wait()
				if err != nil && *debug {
					log.Println("Closing SSH connection:", err)
				}

				select {
				case <-holderConn.Close:
					break
				default:
					holderConn.CleanUp(state)
				}
			}()

			go handleRequests(reqs, holderConn, state)
			go handleChannels(chans, holderConn, state)

			if *cleanupUnbound {
				go func() {
					select {
					case <-time.After(1 * time.Second):
						count := 0
						holderConn.Listeners.Range(func(key, value interface{}) bool {
							count++
							return true
						})

						if count == 0 {
							sendMessage(holderConn, "No forwarding requests sent. Closing connection.", true)
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
	s.SSHConn.Close()
	state.SSHConnections.Delete(s.SSHConn.RemoteAddr())
	log.Println("Closed SSH connection for:", s.SSHConn.RemoteAddr(), "user:", s.SSHConn.User())
}
