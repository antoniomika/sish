package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const (
	// commandSplitter is the character that terminates a prefix.
	commandSplitter = "="

	// proxyProtocolPrefix is used when deciding what proxy protocol
	// version to use.
	proxyProtocolPrefix = "proxy-protocol"

	// proxyProtoPrefixLegacy is used when deciding what proxy protocol
	// version to use.
	proxyProtoPrefixLegacy = "proxyproto"

	// hostHeaderPrefix is the host-header for a specific session.
	hostHeaderPrefix = "host-header"

	// stripPathPrefix defines whether or not to strip the path (if enabled globally).
	stripPathPrefix = "strip-path"

	// sniProxyPrefix defines whether or not to enable SNI Proxying (if enabled globally).
	sniProxyPrefix = "sni-proxy"

	// tcpAliasPrefix defines whether or not to enable TCP Aliasing (if enabled globally).
	tcpAliasPrefix = "tcp-alias"

	// localForwardPrefix defines whether or not a local forward is being used (allows for logging).
	localForwardPrefix = "local-forward"

	// autoClosePrefix defines whether or not a connection will close when all forwards are cleaned up.
	autoClosePrefix = "auto-close"

	// forceHTTPSPrefix defines whether or not a connection will redirect to https.
	forceHTTPSPrefix = "force-https"

	// tcpAddressPrefix defines whether or not to set the tcp address for a tcp forward.
	tcpAddressPrefix = "tcp-address"

	// tcpAliasesAllowedUsersPrefix defines a comma separated list of allowed key fingerprints to access TCP aliases.
	tcpAliasesAllowedUsersPrefix = "tcp-aliases-allowed-users"

	// deadlinePrefix defines a timestamp at which the connection will close automatically.
	deadlinePrefix = "deadline"
)

// handleSession handles the channel when a user requests a session.
// This is how we send console messages.
func handleSession(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	if viper.GetBool("debug") {
		log.Println("Handling session for connection:", connection)
	}

	welcomeMessage := viper.GetString("welcome-message")
	if welcomeMessage != "" {
		writeToSession(connection, aurora.BgRed(welcomeMessage).String()+"\r\n")
	}

	go func() {
		for {
			select {
			case c := <-sshConn.Messages:
				writeToSession(connection, c)
			case <-sshConn.Close:
				return
			}
		}
	}()

	go func() {
		for {
			data := make([]byte, 4096)
			dataRead, err := connection.Read(data)
			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				select {
				case <-sshConn.Close:
					break
				default:
					sshConn.CleanUp(state)
				}
				break
			}

			if dataRead != 0 {
				if data[0] == 3 {
					sshConn.CleanUp(state)
				}
			}
		}
	}()

	go func() {
		sshConn.StripPath = viper.GetBool("strip-http-path")

		for req := range requests {
			switch req.Type {
			case "shell":
				err := req.Reply(true, nil)
				if err != nil {
					log.Println("Error replying to socket request:", err)
				}

				close(sshConn.Exec)
			case "exec":
				payloadString := string(req.Payload[4:])
				commandFlags := strings.Fields(payloadString)

				for _, commandFlag := range commandFlags {
					commandFlagParts := strings.Split(commandFlag, commandSplitter)

					if len(commandFlagParts) < 2 {
						continue
					}

					command, param := commandFlagParts[0], commandFlagParts[1]

					switch command {
					case proxyProtocolPrefix:
						fallthrough
					case proxyProtoPrefixLegacy:
						if !viper.GetBool("proxy-protocol") {
							break
						}
						sshConn.ProxyProto = getProxyProtoVersion(param)
						if sshConn.ProxyProto != 0 {
							sshConn.SendMessage(fmt.Sprintf("Proxy protocol enabled for TCP connections. Using protocol version %d", int(sshConn.ProxyProto)), true)
						}
					case hostHeaderPrefix:
						if !viper.GetBool("rewrite-host-header") {
							break
						}
						sshConn.HostHeader = param
						sshConn.SendMessage(fmt.Sprintf("Using host header %s for HTTP handlers", sshConn.HostHeader), true)
					case stripPathPrefix:
						if !sshConn.StripPath {
							break
						}

						nstripPath, err := strconv.ParseBool(param)

						if err != nil {
							log.Printf("Unable to detect strip path setting. Using configuration: %s", err)
						} else {
							sshConn.StripPath = nstripPath
						}

						sshConn.SendMessage(fmt.Sprintf("Strip path for HTTP handlers set to: %t", sshConn.StripPath), true)
					case sniProxyPrefix:
						if !viper.GetBool("sni-proxy") {
							break
						}

						sniProxy, err := strconv.ParseBool(param)

						if err != nil {
							log.Printf("Unable to detect sni proxy setting. Using false as default: %s", err)
						}

						sshConn.SNIProxy = sniProxy

						sshConn.SendMessage(fmt.Sprintf("SNI proxy for TCP forwards set to: %t", sshConn.SNIProxy), true)
					case tcpAddressPrefix:
						if viper.GetBool("force-tcp-address") {
							break
						}

						sshConn.TCPAddress = param

						sshConn.SendMessage(fmt.Sprintf("TCP address for TCP forwards set to: %s", sshConn.TCPAddress), true)
					case tcpAliasPrefix:
						if !viper.GetBool("tcp-aliases") {
							break
						}

						tcpAlias, err := strconv.ParseBool(param)

						if err != nil {
							log.Printf("Unable to detect tcp alias setting. Using false as default: %s", err)
						}

						sshConn.TCPAlias = tcpAlias

						sshConn.SendMessage(fmt.Sprintf("TCP alias for TCP forwards set to: %t", sshConn.TCPAlias), true)
					case autoClosePrefix:
						autoClose, err := strconv.ParseBool(param)

						if err != nil {
							log.Printf("Unable to detect auto close setting. Using false as default: %s", err)
						}

						sshConn.AutoClose = autoClose

						sshConn.SendMessage(fmt.Sprintf("Auto close for connection set to: %t", sshConn.AutoClose), true)
					case forceHTTPSPrefix:
						if !viper.GetBool("force-https") {
							break
						}

						forceHTTPS, err := strconv.ParseBool(param)
						if err != nil {
							log.Printf("Unable to detect force https setting. Using false as default: %s", err)
						}
						sshConn.ForceHTTPS = forceHTTPS
						sshConn.SendMessage(fmt.Sprintf("Force https for connection set to: %t", sshConn.ForceHTTPS), true)
					case localForwardPrefix:
						localForward, err := strconv.ParseBool(param)

						if err != nil {
							log.Printf("Unable to detect tcp alias setting. Using false as default: %s", err)
						}

						sshConn.LocalForward = localForward

						sshConn.SendMessage(fmt.Sprintf("Connection used for local forwards set to: %t", sshConn.LocalForward), true)
					case tcpAliasesAllowedUsersPrefix:
						if !viper.GetBool("tcp-aliases-allowed-users") {
							break
						}

						fingerPrints := strings.Split(param, ",")

						for i, fingerPrint := range fingerPrints {
							fingerPrints[i] = strings.TrimSpace(fingerPrint)
						}

						connPubKey := ""
						if sshConn.SSHConn.Permissions != nil {
							if _, ok := sshConn.SSHConn.Permissions.Extensions["pubKey"]; ok {
								connPubKey = sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"]
							}
						}

						sshConn.TCPAliasesAllowedUsers = fingerPrints

						printKeys := fingerPrints
						if connPubKey != "" {
							sshConn.TCPAliasesAllowedUsers = append(sshConn.TCPAliasesAllowedUsers, connPubKey)
							printKeys = slices.Insert(printKeys, 0, fmt.Sprintf("%s (self)", connPubKey))
						}

						sshConn.SendMessage(fmt.Sprintf("Allowed users for TCP Aliases set to: %s", strings.Join(printKeys, ", ")), true)
					case deadlinePrefix:
						deadline, err := parseDeadline(param)
						if err != nil {
							log.Printf("Unable to parse deadline: %s", param)
							break
						}

						sshConn.Deadline = &deadline
						sshConn.SendMessage(fmt.Sprintf("Deadline for connection set to: %s", sshConn.Deadline.UTC().Format("2006-01-02 15:04:05")), true)
					}
				}

				close(sshConn.Exec)
			default:
				if viper.GetBool("debug") {
					log.Println("Sub Channel Type", req.Type, req.WantReply, string(req.Payload))
				}
			}
		}
	}()
}

// handleAlias is used when handling a SSH connection to attach to an alias listener.
func handleAlias(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	go ssh.DiscardRequests(requests)

	select {
	case <-sshConn.Exec:
	case <-time.After(1 * time.Second):
		break
	}

	if viper.GetBool("debug") {
		log.Println("Handling alias connection for:", connection)
	}

	check := &forwardedTCPPayload{}
	err = ssh.Unmarshal(newChannel.ExtraData(), check)
	if err != nil {
		log.Println("Error unmarshaling information:", err)
		sshConn.CleanUp(state)
		return
	}

	check.Addr = strings.ToLower(check.Addr)

	tcpAliasToConnect := fmt.Sprintf("%s:%d", check.Addr, check.Port)
	loc, ok := state.AliasListeners.Load(tcpAliasToConnect)
	if !ok {
		log.Println("Unable to load tcp alias:", tcpAliasToConnect)
		sshConn.CleanUp(state)
		return
	}

	aH := loc

	pubKeyFingerprint := ""

	if sshConn.SSHConn.Permissions != nil {
		if _, ok := sshConn.SSHConn.Permissions.Extensions["pubKey"]; ok {
			pubKeyFingerprint = sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"]
		}
	}

	if viper.GetBool("tcp-aliases-allowed-users") {
		connAllowed := false

		aH.SSHConnections.Range(func(name string, conn *utils.SSHConnection) bool {
			for _, fingerprint := range conn.TCPAliasesAllowedUsers {
				if fingerprint == "any" || (fingerprint != "" && pubKeyFingerprint != "" && fingerprint == pubKeyFingerprint) {
					connAllowed = true
					return false
				}
			}
			return true
		})

		if !connAllowed {
			log.Println("Connection not allowed because fingerprint is not found in allowed list")
			sshConn.CleanUp(state)
			return
		}
	}

	connectionLocation, err := aH.Balancer.NextServer()
	if err != nil {
		log.Println("Unable to load connection location:", err)
		sshConn.CleanUp(state)
		return
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		log.Println("Unable to decode connection location:", err)
		sshConn.CleanUp(state)
		return
	}

	aliasAddr := string(host)

	connString := sshConn.SSHConn.RemoteAddr().String()
	if pubKeyFingerprint != "" {
		connString = fmt.Sprintf("%s (%s)", connString, pubKeyFingerprint)
	}

	logLine := fmt.Sprintf("Accepted connection from %s -> %s", connString, tcpAliasToConnect)
	log.Println(logLine)

	if viper.GetBool("log-to-client") {
		aH.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
			sshConn.Listeners.Range(func(listenerAddr string, val net.Listener) bool {
				if listenerAddr == aliasAddr {
					sshConn.SendMessage(logLine, true)

					return false
				}

				return true
			})

			return true
		})

		if sshConn.LocalForward {
			sshConn.SendMessage(logLine, true)
		}
	}

	conn, err := net.Dial("unix", aliasAddr)
	if err != nil {
		log.Println("Error connecting to alias:", err)
		sshConn.CleanUp(state)
		return
	}

	utils.CopyBoth(conn, connection)
}

// writeToSession is where we write to the underlying session channel.
func writeToSession(connection ssh.Channel, c string) {
	_, err := connection.Write(append([]byte(c), []byte{'\r', '\n'}...))
	if err != nil && viper.GetBool("debug") {
		log.Println("Error trying to write message to socket:", err)
	}
}

// getProxyProtoVersion returns the proxy proto version selected by the client.
func getProxyProtoVersion(proxyProtoUserVersion string) byte {
	if viper.GetString("proxy-protocol-version") != "userdefined" {
		proxyProtoUserVersion = viper.GetString("proxy-protocol-version")
	}

	realProtoVersion := 0
	if proxyProtoUserVersion == "1" {
		realProtoVersion = 1
	} else if proxyProtoUserVersion == "2" {
		realProtoVersion = 2
	}

	return byte(realProtoVersion)
}

// parseDeadline parses the deadline string provided by the client to a time object.
func parseDeadline(param string) (time.Time, error) {
	// Try parsing as an epoch time
	if epoch, err := strconv.ParseInt(param, 10, 64); err == nil {
		return time.Unix(epoch, 0), nil
	}

	// Try parsing as a duration
	if duration, err := time.ParseDuration(param); err == nil {
		return time.Now().Add(duration), nil
	}

	// Try parsing as a date-time
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z07:00",
	}
	for _, layout := range layouts {
		if deadline, err := time.Parse(layout, param); err == nil {
			return deadline, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid deadline format")
}
