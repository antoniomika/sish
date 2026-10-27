package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
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

	// logFormatPrefix defines whether messages to the client are text or json.
	logFormatPrefix = "log-format"
)

// handleSession handles the channel when a user requests a session.
// This is how we send console messages.
func handleSession(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	slog.Debug(
		"handling session for connection",
		"connection", connection,
	)

	// The welcome message waits for the shell or exec request, which may ask for json.
	sendWelcome := func() {
		welcomeMessage := viper.GetString("welcome-message")
		if welcomeMessage != "" {
			sshConn.SendLog(slog.LevelInfo, aurora.BgRed(welcomeMessage).String()+"\r\n", welcomeMessage)
		}
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
					slog.Error(
						"error replying to socket request",
						"error", err,
					)
				}

				sendWelcome()
				sshConn.ExecReceived()
			case "exec":
				payloadString := string(req.Payload[4:])
				commandFlags := strings.Fields(payloadString)

				for _, commandFlag := range commandFlags {
					if command, param, ok := strings.Cut(commandFlag, commandSplitter); ok && command == logFormatPrefix {
						sshConn.JSONLogs.Store(param == "json")
					}
				}

				sendWelcome()

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
							sshConn.SendLog(
								slog.LevelInfo,
								fmt.Sprintf("Proxy protocol enabled for TCP connections. Using protocol version %d", int(sshConn.ProxyProto)),
								"option set",
								"option", proxyProtocolPrefix,
								"value", int(sshConn.ProxyProto),
							)
						}
					case hostHeaderPrefix:
						if !viper.GetBool("rewrite-host-header") {
							break
						}
						sshConn.HostHeader = param
						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Using host header %s for HTTP handlers", sshConn.HostHeader),
							"option set",
							"option", hostHeaderPrefix,
							"value", sshConn.HostHeader,
						)
					case stripPathPrefix:
						if !sshConn.StripPath {
							break
						}

						nstripPath, err := strconv.ParseBool(param)

						if err != nil {
							slog.Error(
								"unable to detect strip path setting",
								"error", err,
							)
						} else {
							sshConn.StripPath = nstripPath
						}

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Strip path for HTTP handlers set to: %t", sshConn.StripPath),
							"option set",
							"option", stripPathPrefix,
							"value", sshConn.StripPath,
						)
					case sniProxyPrefix:
						if !viper.GetBool("sni-proxy") {
							break
						}

						sniProxy, err := strconv.ParseBool(param)

						if err != nil {
							slog.Error(
								"unable to detect sni proxy setting",
								"error", err,
							)
						}

						sshConn.SNIProxy = sniProxy

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("SNI proxy for TCP forwards set to: %t", sshConn.SNIProxy),
							"option set",
							"option", sniProxyPrefix,
							"value", sshConn.SNIProxy,
						)
					case tcpAddressPrefix:
						if viper.GetBool("force-tcp-address") {
							break
						}

						sshConn.TCPAddress = param

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("TCP address for TCP forwards set to: %s", sshConn.TCPAddress),
							"option set",
							"option", tcpAddressPrefix,
							"value", sshConn.TCPAddress,
						)
					case tcpAliasPrefix:
						if !viper.GetBool("tcp-aliases") {
							break
						}

						tcpAlias, err := strconv.ParseBool(param)

						if err != nil {
							slog.Error(
								"unable to detect tcp alias setting",
								"error", err,
							)
						}

						sshConn.TCPAlias = tcpAlias

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("TCP alias for TCP forwards set to: %t", sshConn.TCPAlias),
							"option set",
							"option", tcpAliasPrefix,
							"value", sshConn.TCPAlias,
						)
					case autoClosePrefix:
						autoClose, err := strconv.ParseBool(param)

						if err != nil {
							slog.Error(
								"unable to detect auto close setting",
								"error", err,
							)
						}

						sshConn.AutoClose = autoClose

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Auto close for connection set to: %t", sshConn.AutoClose),
							"option set",
							"option", autoClosePrefix,
							"value", sshConn.AutoClose,
						)
					case forceHTTPSPrefix:
						if !viper.GetBool("force-https") {
							break
						}

						forceHTTPS, err := strconv.ParseBool(param)
						if err != nil {
							slog.Error(
								"unable to detect force https setting",
								"error", err,
							)
						}
						sshConn.ForceHTTPS = forceHTTPS
						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Force https for connection set to: %t", sshConn.ForceHTTPS),
							"option set",
							"option", forceHTTPSPrefix,
							"value", sshConn.ForceHTTPS,
						)
					case localForwardPrefix:
						localForward, err := strconv.ParseBool(param)

						if err != nil {
							slog.Error(
								"unable to detect tcp alias setting",
								"error", err,
							)
						}

						sshConn.LocalForward = localForward

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Connection used for local forwards set to: %t", sshConn.LocalForward),
							"option set",
							"option", localForwardPrefix,
							"value", sshConn.LocalForward,
						)
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

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Allowed users for TCP Aliases set to: %s", strings.Join(printKeys, ", ")),
							"option set",
							"option", tcpAliasesAllowedUsersPrefix,
							"value", sshConn.TCPAliasesAllowedUsers,
						)
					case logFormatPrefix:
						logFormat := "text"
						if sshConn.JSONLogs.Load() {
							logFormat = "json"
						}

						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Log format for connection set to: %s", logFormat),
							"option set",
							"option", logFormatPrefix,
							"value", logFormat,
						)
					case deadlinePrefix:
						deadline, err := parseDeadline(param)
						if err != nil {
							slog.Error(
								"unable to parse deadline",
								"error", err,
								"param", param,
							)
							break
						}

						sshConn.Deadline = &deadline
						sshConn.SendLog(
							slog.LevelInfo,
							fmt.Sprintf("Deadline for connection set to: %s", sshConn.Deadline.UTC().Format("2006-01-02 15:04:05")),
							"option set",
							"option", deadlinePrefix,
							"value", sshConn.Deadline.UTC(),
						)
					}
				}

				err := req.Reply(true, nil)
				if err != nil {
					slog.Error(
						"error replying to socket request",
						"error", err,
					)
				}

				sshConn.ExecReceived()
			default:
				err := req.Reply(req.Type == "pty-req", nil)
				if err != nil {
					slog.Error(
						"error replying to socket request",
						"error", err,
					)
				}

				slog.Debug(
					"sub channel type",
					"type", req.Type,
					"wantReply", req.WantReply,
					"payload", req.Payload,
				)
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

	slog.Debug(
		"handling alias connection",
		"connection", connection,
	)

	check := &forwardedTCPPayload{}
	err = ssh.Unmarshal(newChannel.ExtraData(), check)
	if err != nil {
		slog.Error(
			"error unmarshaling information",
			"error", err,
		)
		sshConn.CleanUp(state)
		return
	}

	check.Addr = strings.ToLower(check.Addr)

	tcpAliasToConnect := fmt.Sprintf("%s:%d", check.Addr, check.Port)
	loc, ok := state.AliasListeners.Load(tcpAliasToConnect)
	if !ok {
		slog.Error(
			"unable to load tcp alias",
			"ok", ok,
		)
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
			slog.Info("connection not allowed because fingerprint is not found in allowed list")
			sshConn.CleanUp(state)
			return
		}
	}

	connectionLocation, err := aH.Balancer.NextServer()
	if err != nil {
		slog.Error(
			"error selecting next server",
			"error", err,
		)
		sshConn.CleanUp(state)
		return
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		slog.Error(
			"error decoding server",
			"error", err,
		)
		sshConn.CleanUp(state)
		return
	}

	aliasAddr := string(host)

	connString := sshConn.SSHConn.RemoteAddr().String()
	if pubKeyFingerprint != "" {
		connString = fmt.Sprintf("%s [%s (%s)]", connString, pubKeyFingerprint, sshConn.User())
	}

	logLine := fmt.Sprintf("Accepted alias connection from %s -> %s", connString, tcpAliasToConnect)

	ev := utils.ConnectionEvent{
		SSHConn:        sshConn,
		TunnelType:     "alias",
		TunnelId:       aH.TunnelId(),
		ConnectionType: "tcp",
		RemoteAddr:     connString,
		LocalAddr:      tcpAliasToConnect,
	}

	state.LogConnection(ev)

	if viper.GetBool("log-to-client") {
		if owner := utils.ListenerOwner(aH.SSHConnections, aliasAddr); owner != nil {
			owner.SendConnection(logLine, ev)
		}

		if sshConn.LocalForward {
			sshConn.SendConnection(logLine, ev)
		}
	}

	conn, err := net.Dial("unix", aliasAddr)
	if err != nil {
		slog.Error(
			"error connecting to alias",
			"error", err,
		)
		sshConn.CleanUp(state)
		return
	}

	utils.CopyBoth(conn, connection)
}

// writeToSession is where we write to the underlying session channel.
func writeToSession(connection ssh.Channel, c string) {
	_, err := connection.Write(append([]byte(c), []byte{'\r', '\n'}...))
	if err != nil {
		slog.Debug(
			"error trying to write message to session",
			"error", err,
		)
	}
}

// getProxyProtoVersion returns the proxy proto version selected by the client.
func getProxyProtoVersion(proxyProtoUserVersion string) byte {
	if viper.GetString("proxy-protocol-version") != "userdefined" {
		proxyProtoUserVersion = viper.GetString("proxy-protocol-version")
	}

	switch proxyProtoUserVersion {
	case "1":
		return 1
	case "2":
		return 2
	default:
		return 0
	}
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
