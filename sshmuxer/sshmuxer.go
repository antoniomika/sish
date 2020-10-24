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

	"github.com/antoniomika/go-proxyproto"
	"github.com/antoniomika/sish/httpmuxer"
	"github.com/antoniomika/sish/utils"
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

	utils.WatchCerts()

	state := utils.NewState()
	state.Console.State = state

	go httpmuxer.Start(state)

	if viper.GetBool("debug") {
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
				state.AliasListeners.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Println("===Web Console Routes====")
				state.Console.Clients.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Println("===Web Console Tokens====")
				state.Console.RouteTokens.Range(func(key, value interface{}) bool {
					log.Println(key, value)
					return true
				})
				log.Print("========End==========\n")

				time.Sleep(2 * time.Second)
			}
		}()
	}

	log.Println("Starting SSH service on address:", viper.GetString("ssh-address"))

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

		if err != nil || state.IPFilter.Blocked(clientRemote) {
			conn.Close()
			continue
		}

		clientLoggedInMutex := &sync.Mutex{}

		clientLoggedInMutex.Lock()
		clientLoggedIn := false
		clientLoggedInMutex.Unlock()

		if viper.GetBool("cleanup-unbound") {
			go func() {
				<-time.After(viper.GetDuration("cleanup-unbound-timeout"))
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
				return
			}

			holderConn := &utils.SSHConnection{
				SSHConn:   sshConn,
				Listeners: &sync.Map{},
				Closed:    &sync.Once{},
				Close:     make(chan bool),
				Messages:  make(chan string),
				Session:   make(chan bool),
				SetupLock: &sync.Mutex{},
			}

			state.SSHConnections.Store(sshConn.RemoteAddr().String(), holderConn)

			go func() {
				err := sshConn.Wait()
				if err != nil && viper.GetBool("debug") {
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

			if viper.GetBool("cleanup-unbound") {
				go func() {
					select {
					case <-time.After(viper.GetDuration("cleanup-unbound-timeout")):
						count := 0
						holderConn.Listeners.Range(func(key, value interface{}) bool {
							count++
							return true
						})

						if count == 0 {
							holderConn.SendMessage("No forwarding requests sent. Closing connection.", true)
							time.Sleep(1 * time.Millisecond)
							holderConn.CleanUp(state)
						}
					case <-holderConn.Close:
						return
					}
				}()
			}

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
								log.Println("Error retrieving keepalive response:", err)
								return
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
