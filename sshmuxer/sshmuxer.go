// Package sshmuxer handles the underlying SSH server
// and multiplexing forwarding sessions.
package sshmuxer

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/antoniomika/sish/httpmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// Start initializes the ssh muxer service. It will start necessary components
// and begin listening for SSH connections.
func Start() {
	var (
		httpPort  int
		httpsPort int
		sshPort   int
	)

	_, httpPortString, err := utils.ParseAddress(viper.GetString("http-address"))
	if err != nil {
		utils.Fatal(
			"unable to parse address",
			"address", viper.GetString("http-address"),
			"err", err,
		)
	}

	_, httpsPortString, err := utils.ParseAddress(viper.GetString("https-address"))
	if err != nil {
		utils.Fatal(
			"unable to parse address",
			"address", viper.GetString("https-address"),
			"err", err,
		)
	}

	_, sshPortString, err := utils.ParseAddress(viper.GetString("ssh-address"))
	if err != nil {
		utils.Fatal(
			"unable to parse address",
			"address", viper.GetString("ssh-address"),
			"err", err,
		)
	}

	httpPort, err = strconv.Atoi(httpPortString)
	if err != nil {
		utils.Fatal(
			"unable to parse port",
			"port", httpPortString,
			"err", err,
		)
	}

	httpsPort, err = strconv.Atoi(httpsPortString)
	if err != nil {
		utils.Fatal(
			"unable to parse port",
			"port", httpsPortString,
			"err", err,
		)
	}

	sshPort, err = strconv.Atoi(sshPortString)
	if err != nil {
		utils.Fatal(
			"unable to parse port",
			"port", sshPortString,
			"err", err,
		)
	}

	if viper.GetInt("http-port-override") != 0 {
		httpPort = viper.GetInt("http-port-override")
	}

	if viper.GetInt("https-port-override") != 0 {
		httpsPort = viper.GetInt("https-port-override")
	}

	utils.WatchKeys()

	state := utils.NewState()
	state.Ports.HTTPPort = httpPort
	state.Ports.HTTPSPort = httpsPort
	state.Ports.SSHPort = sshPort

	state.Console.State = state

	go httpmuxer.Start(state)

	debugInterval := viper.GetDuration("debug-interval")

	if viper.GetBool("debug") && debugInterval > 0 {
		go func() {
			for {
				remoteAddrs := func(conns *syncmap.Map[string, *utils.SSHConnection]) []string {
					addrs := []string{}
					conns.Range(func(_ string, conn *utils.SSHConnection) bool {
						addrs = append(addrs, conn.SSHConn.RemoteAddr().String())
						return true
					})
					return addrs
				}

				listeners := []string{}
				state.Listeners.Range(func(key string, _ net.Listener) bool {
					listeners = append(listeners, key)
					return true
				})

				clients := map[string]any{}
				state.SSHConnections.Range(func(key string, value *utils.SSHConnection) bool {
					names := []string{}
					value.Listeners.Range(func(name string, _ net.Listener) bool {
						names = append(names, name)
						return true
					})

					clients[key] = map[string]any{"user": value.User(), "listeners": names}
					return true
				})

				httpListeners := map[string][]string{}
				state.HTTPListeners.Range(func(key string, value *utils.HTTPHolder) bool {
					httpListeners[key] = remoteAddrs(value.SSHConnections)
					return true
				})

				aliasListeners := map[string][]string{}
				state.AliasListeners.Range(func(key string, value *utils.AliasHolder) bool {
					aliasListeners[key] = remoteAddrs(value.SSHConnections)
					return true
				})

				tcpListeners := map[string][]string{}
				state.TCPListeners.Range(func(key string, value *utils.TCPHolder) bool {
					tcpListeners[key] = remoteAddrs(value.SSHConnections)
					return true
				})

				consoleClients := map[string][]string{}
				state.Console.Clients.Range(func(key string, value []*utils.WebClient) bool {
					addrs := []string{}
					for _, cl := range value {
						addrs = append(addrs, cl.Conn.RemoteAddr().String())
					}

					consoleClients[key] = addrs
					return true
				})

				// Only the routes, since the tokens grant console access.
				consoleRoutes := []string{}
				state.Console.RouteTokens.Range(func(key, _ string) bool {
					consoleRoutes = append(consoleRoutes, key)
					return true
				})

				slog.Debug(
					"server state",
					"goroutines", runtime.NumGoroutine(),
					"listeners", listeners,
					"clients", clients,
					"httpListeners", httpListeners,
					"aliasListeners", aliasListeners,
					"tcpListeners", tcpListeners,
					"consoleClients", consoleClients,
					"consoleRoutes", consoleRoutes,
				)

				time.Sleep(debugInterval)
			}
		}()
	}

	slog.Info(
		"starting SSH service",
		"address", viper.GetString("ssh-address"),
	)

	sshConfig := utils.GetSSHConfig()

	var listener net.Listener

	l, err := utils.Listen(viper.GetString("ssh-address"))
	if err != nil {
		utils.Fatal(
			"unable to listen",
			"address", viper.GetString("ssh-address"),
			"err", err,
		)
	}

	if viper.GetBool("proxy-protocol-listener") {
		hListener := &proxyproto.Listener{
			Listener: l,
		}

		utils.LoadProxyProtoConfig(hListener)
		listener = hListener
	} else {
		listener = l
	}

	state.Listeners.Store(viper.GetString("ssh-address"), listener)

	defer func() {
		err := listener.Close()
		if err != nil {
			slog.Error(
				"error closing listener",
				"err", err,
			)
		}

		state.Listeners.Delete(viper.GetString("ssh-address"))
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
			slog.Error(
				"error accepting from listener",
				"err", err,
			)
			continue
		}

		go handleConn(conn, state, sshConfig)
	}
}

// handleConn handles a single accepted SSH connection: it performs the SSH
// handshake and wires up the per-connection goroutines (cleanup on close,
// request/channel handling, unbound/deadline cleanup and keepalives). It is
// split out of Start so the connection lifecycle can be exercised by tests.
func handleConn(conn net.Conn, state *utils.State, sshConfig *ssh.ServerConfig) {
	clientRemote, _, err := net.SplitHostPort(conn.RemoteAddr().String())

	if err != nil || state.IPFilter.Blocked(clientRemote) {
		err := conn.Close()
		if err != nil {
			slog.Error(
				"error closing new conn",
				"err", err,
			)
		}

		if viper.GetBool("debug") {
			slog.Debug(
				"blocked connection",
				"remoteAddr", conn.RemoteAddr().String(),
				"localAddr", conn.LocalAddr().String(),
			)
		}

		return
	}

	clientLoggedInMutex := &sync.Mutex{}

	clientLoggedInMutex.Lock()
	clientLoggedIn := false
	clientLoggedInMutex.Unlock()

	if viper.GetBool("cleanup-unauthed") {
		go func() {
			<-time.After(viper.GetDuration("cleanup-unauthed-timeout"))
			clientLoggedInMutex.Lock()
			if !clientLoggedIn {
				err := conn.Close()
				if err != nil {
					slog.Error(
						"error closing unauthenticated connection",
						"err", err,
					)
				}
			}
			clientLoggedInMutex.Unlock()
		}()
	}

	slog.Info(
		"accepted ssh connection",
		"remoteAddr", conn.RemoteAddr().String(),
	)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	clientLoggedInMutex.Lock()
	clientLoggedIn = true
	clientLoggedInMutex.Unlock()
	if err != nil {
		err := conn.Close()
		if err != nil {
			slog.Error(
				"error closing connection",
				"err", err,
			)
		}
		return
	}

	pubKeyFingerprint := ""

	if sshConn.Permissions != nil {
		if _, ok := sshConn.Permissions.Extensions["pubKey"]; ok {
			pubKeyFingerprint = sshConn.Permissions.Extensions["pubKeyFingerprint"]
		}
	}

	holderConn := &utils.SSHConnection{
		SSHConn:                sshConn,
		Listeners:              syncmap.New[string, net.Listener](),
		Closed:                 &sync.Once{},
		Close:                  make(chan bool),
		Exec:                   make(chan bool),
		Messages:               make(chan string),
		Session:                make(chan bool),
		SetupLock:              &sync.Mutex{},
		TCPAliasesAllowedUsers: []string{pubKeyFingerprint},
		ConnectedAt:            time.Now(),
	}

	state.SSHConnections.Store(sshConn.RemoteAddr().String(), holderConn)

	go func() {
		err := sshConn.Wait()
		if err != nil {
			slog.Debug(
				"closing SSH connection",
				"err", err,
			)
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

	go func() {
		select {
		case <-holderConn.Exec:
		case <-time.After(1 * time.Second):
			break
		}

		runTime := 0.0
		ticker := time.NewTicker(1 * time.Second)

		for {
			select {
			case <-ticker.C:
				runTime++

				if holderConn.Deadline != nil && time.Now().After(*holderConn.Deadline) {
					holderConn.SendLog(slog.LevelInfo, "Connection deadline reached. Closing connection.", "connection deadline reached")
					time.Sleep(1 * time.Millisecond)
					holderConn.CleanUp(state)
					return
				}

				if ((viper.GetBool("cleanup-unbound") && runTime > viper.GetDuration("cleanup-unbound-timeout").Seconds()) || holderConn.AutoClose) && holderConn.ListenerCount() == 0 {
					holderConn.SendLog(slog.LevelInfo, "No forwarding requests sent. Closing connection.", "no forwarding requests sent")
					time.Sleep(1 * time.Millisecond)
					holderConn.CleanUp(state)
				}
			case <-holderConn.Close:
				return
			}
		}
	}()

	if viper.GetBool("ping-client") {
		go func() {
			tickDuration := viper.GetDuration("ping-client-interval")
			ticker := time.NewTicker(tickDuration)

			for {
				err := conn.SetDeadline(time.Now().Add(tickDuration).Add(viper.GetDuration("ping-client-timeout")))
				if err != nil {
					slog.Error(
						"unable to set deadline",
						"err", err,
					)
				}

				select {
				case <-ticker.C:
					_, _, err := sshConn.SendRequest("keepalive@sish", true, nil)
					if err != nil {
						slog.Error(
							"error retrieving keepalive response",
							"err", err,
						)
						return
					}
				case <-holderConn.Close:
					return
				}
			}
		}()
	}
}
