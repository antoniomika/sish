// Package sshmuxer handles the underlying SSH server
// and multiplexing forwarding sessions.
package sshmuxer

import (
	"log"
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

var (
	// httpPort is used as a string override for the used HTTP port.
	httpPort int

	// httpsPort is used as a string override for the used HTTPS port.
	httpsPort int
)

// Start initializes the ssh muxer service. It will start necessary components
// and begin listening for SSH connections.
func Start() {
	_, httpPortString, err := net.SplitHostPort(viper.GetString("http-address"))
	if err != nil {
		log.Fatalln("Error parsing address:", err)
	}

	_, httpsPortString, err := net.SplitHostPort(viper.GetString("https-address"))
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

	if viper.GetInt("http-port-override") != 0 {
		httpPort = viper.GetInt("http-port-override")
	}

	if viper.GetInt("https-port-override") != 0 {
		httpsPort = viper.GetInt("https-port-override")
	}

	utils.WatchKeys()

	state := utils.NewState()
	state.Console.State = state

	go httpmuxer.Start(state)

	debugInterval := viper.GetDuration("debug-interval")

	if viper.GetBool("debug") && debugInterval > 0 {
		go func() {
			for {
				log.Println("=======Start=========")
				log.Println("===Goroutines=====")
				log.Println(runtime.NumGoroutine())
				log.Println("===Listeners======")
				state.Listeners.Range(func(key string, value net.Listener) bool {
					log.Println(key)
					return true
				})
				log.Println("===Clients========")
				state.SSHConnections.Range(func(key string, value *utils.SSHConnection) bool {
					listeners := []string{}
					value.Listeners.Range(func(name string, listener net.Listener) bool {
						listeners = append(listeners, name)
						return true
					})

					log.Println(key, value.SSHConn.User(), listeners)
					log.Println("Metrics:", value.Created.Format(time.RFC3339),
						"Duration:", time.Since(value.Created).Round(time.Second))
					return true
				})
				log.Println("===HTTP Listeners===")
				state.HTTPListeners.Range(func(key string, value *utils.HTTPHolder) bool {
					clients := []string{}
					value.SSHConnections.Range(func(name string, conn *utils.SSHConnection) bool {
						clients = append(clients, conn.SSHConn.RemoteAddr().String())
						return true
					})

					log.Println(key, clients)
					return true
				})
				log.Println("===TCP Aliases====")
				state.AliasListeners.Range(func(key string, value *utils.AliasHolder) bool {
					clients := []string{}
					value.SSHConnections.Range(func(name string, conn *utils.SSHConnection) bool {
						clients = append(clients, conn.SSHConn.RemoteAddr().String())
						return true
					})

					log.Println(key, clients)
					return true
				})
				log.Println("===TCP Listeners====")
				state.TCPListeners.Range(func(key string, value *utils.TCPHolder) bool {
					clients := []string{}
					value.SSHConnections.Range(func(name string, conn *utils.SSHConnection) bool {
						clients = append(clients, conn.SSHConn.RemoteAddr().String())
						return true
					})

					log.Println(key, clients)
					return true
				})
				log.Println("===Web Console Routes====")
				state.Console.Clients.Range(func(key string, value []*utils.WebClient) bool {
					newData := []string{}
					for _, cl := range value {
						newData = append(newData, cl.Conn.RemoteAddr().String())
					}

					log.Println(key, newData)
					return true
				})
				log.Println("===Web Console Tokens====")
				state.Console.RouteTokens.Range(func(key, value string) bool {
					log.Println(key, value)
					return true
				})
				log.Print("========End==========\n")

				time.Sleep(debugInterval)
			}
		}()
	}

	log.Println("Starting SSH service on address:", viper.GetString("ssh-address"), "httpPort:", httpPort, "httpsPort", httpsPort)

	sshConfig := utils.GetSSHConfig()

	var listener net.Listener

	l, err := net.Listen("tcp", viper.GetString("ssh-address"))
	if err != nil {
		log.Fatal(err)
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
		listener.Close()
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
			log.Println(err)
			continue
		}

		clientRemote, _, err := net.SplitHostPort(conn.RemoteAddr().String())

		if err != nil || state.IPFilter.Blocked(clientRemote) || state.RetryTimer.Blocked(clientRemote) {
			conn.Close()
			continue
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
					conn.Close()
				}
				clientLoggedInMutex.Unlock()
			}()
		}

		log.Println("Accepted SSH connection for:", conn.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			clientLoggedInMutex.Lock()
			clientLoggedIn = true
			clientLoggedInMutex.Unlock()
			if err != nil {
				conn.Close()
				log.Println(err)
				state.RetryTimer.TryLater(clientRemote)
				return
			}

			if state.RetryTimer.Find(clientRemote) {
				state.RetryTimer.Reset(clientRemote)
			}

			holderConn := &utils.SSHConnection{
				SSHConn:   sshConn,
				Listeners: syncmap.New[string, net.Listener](),
				Closed:    &sync.Once{},
				Close:     make(chan bool),
				Exec:      make(chan bool),
				Messages:  make(chan string),
				Session:   make(chan bool),
				SetupLock: &sync.Mutex{},
				Created:   time.Now(),
			}

			state.SSHConnections.Store(sshConn.RemoteAddr().String(), holderConn)

			// History
			histConnect := updateHistory(sshConn, clientRemote, state)

			go func() {
				err := sshConn.Wait()
				if err != nil && viper.GetBool("debug") {
					log.Println("Closing SSH connection:", err)
				}
				histConnect.Finished = time.Now().Unix()
				histConnect.Duration = histConnect.Finished - histConnect.Started

				select {
				case <-holderConn.Close:
					break
				default:
					holderConn.CleanUp(state)
				}
			}()

			log.Println("444444", len(reqs))
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

						if ((viper.GetBool("cleanup-unbound") && runTime > viper.GetDuration("cleanup-unbound-timeout").Seconds()) || holderConn.AutoClose) && holderConn.ListenerCount() == 0 {
							holderConn.SendMessage("No forwarding requests sent. Closing connection.", true)
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
							log.Println("Unable to set deadline")
						}

						select {
						case <-ticker.C:
							_, _, err := sshConn.SendRequest("keepalive@sish", true, nil)
							if err != nil {
								log.Println("Error retrieving keepalive response: from ", clientRemote, err.Error())
								return
							}
							if viper.GetBool("debug") {
								log.Println("ticker expired for : ", clientRemote)
							}
						case <-holderConn.Close:
							return
						}
					}
				}()
			}
		}()
	}
}

func updateHistory(sshConn *ssh.ServerConn, clientRemote string, state *utils.State) *utils.ConnectionHistory {
	histKey := sshConn.User() + "-" + clientRemote
	hist, _ := state.History.Load(histKey)
	if hist == nil {
		hist = &utils.HistoryHolder{
			ConnectsCount: 0,
			Connects:      []*utils.ConnectionHistory{},
		}
		state.History.Store(histKey, hist)
	}
	hist.ConnectsCount++
	histConnect := &utils.ConnectionHistory{
		Started: time.Now().Unix(),
	}
	hist.Connects = append(hist.Connects, histConnect)
	return histConnect
}
