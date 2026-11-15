package sshmuxer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

// handleAliasListener handles the creation of the aliasHandler
// (or addition for load balancing) and sets up the underlying listeners.
func handleAliasListener(check *channelForwardMsg, stringPort string, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.AliasHolder, *url.URL, string, string, error) {
	validAlias, aH := utils.GetOpenAlias(check.Addr, stringPort, state, sshConn)

	if !strings.HasPrefix(validAlias, check.Addr) && viper.GetBool("force-requested-aliases") || validAlias == "" {
		return nil, nil, "", "", fmt.Errorf("error assigning requested alias to tunnel")
	}

	created := aH == nil

	if aH == nil {
		lb, err := roundrobin.New(nil)

		if err != nil {
			slog.Error(
				"error initializing alias balancer",
				"err", err,
			)
			return nil, nil, "", "", err
		}

		aH = &utils.AliasHolder{
			AliasHost:      validAlias,
			SSHConnections: syncmap.New[string, *utils.SSHConnection](),
			Balancer:       lb,
		}
	}

	// Teardown removes a holder under the same lock once its last backend leaves.
	state.BindLock.Lock()
	defer state.BindLock.Unlock()

	if created {
		// Another binding may have taken the alias since it was checked.
		if _, exists := state.AliasListeners.Load(validAlias); exists {
			return nil, nil, "", "", fmt.Errorf("alias %s was bound by another tunnel", validAlias)
		}

		state.AliasListeners.Store(validAlias, aH)
	} else if registered, ok := state.AliasListeners.Load(validAlias); !ok || registered != aH {
		return nil, nil, "", "", fmt.Errorf("load balancer for alias %s closed while binding", validAlias)
	}

	aH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host: base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
	}

	err := aH.Balancer.UpsertServer(serverURL)
	if err != nil {
		slog.Error(
			"error adding server to balancer",
			"err", err,
		)
	}

	requestMessages += sshConn.FormatLog(
		slog.LevelInfo,
		fmt.Sprintf("%s: %s\r\n", aurora.BgBlue("TCP Alias"), validAlias),
		"forwarding started",
		"forwardingType", "TCP Alias",
		"alias", validAlias,
	)
	sshConn.Logger().Info(
		"forwarding started",
		"forwardingType", "TCP Alias",
		"alias", validAlias,
		"listenerAddr", listenerHolder.Addr().String(),
	)

	return aH, serverURL, validAlias, requestMessages, nil
}

// errAliasNotAllowed is returned when no backend of an alias permits the client.
var errAliasNotAllowed = errors.New("fingerprint not allowed by any alias backend")

// aliasAllowsFingerprint reports whether the alias owner permits a client with this key fingerprint.
func aliasAllowsFingerprint(owner *utils.SSHConnection, fingerprint string) bool {
	for _, allowed := range owner.TCPAliasesAllowedUsers {
		if allowed == "any" || (allowed != "" && fingerprint != "" && allowed == fingerprint) {
			return true
		}
	}

	return false
}

// selectAliasBackend returns the listener address of the next backend for an
// alias connection. With checkAllowed, a backend is only eligible if its own
// owner allows the fingerprint, since co-bound owners can have different
// allowlists.
func selectAliasBackend(aH *utils.AliasHolder, fingerprint string, checkAllowed bool) (string, error) {
	if !checkAllowed {
		server, err := aH.Balancer.NextServer()
		if err != nil {
			return "", err
		}

		return decodeAliasServer(server)
	}

	allowed := func(server *url.URL) (string, bool) {
		addr, err := decodeAliasServer(server)
		if err != nil {
			return "", false
		}

		owner, ok := aH.SSHConnections.Load(addr)

		return addr, ok && aliasAllowsFingerprint(owner, fingerprint)
	}

	servers := aH.Balancer.Servers()

	// Walk the round robin first so allowed backends still share load.
	for range servers {
		server, err := aH.Balancer.NextServer()
		if err != nil {
			return "", err
		}

		if addr, ok := allowed(server); ok {
			return addr, nil
		}
	}

	// Concurrent connections advance the same round robin, so a full walk can
	// still skip an allowed backend.
	for _, server := range servers {
		if addr, ok := allowed(server); ok {
			return addr, nil
		}
	}

	return "", errAliasNotAllowed
}

func decodeAliasServer(server *url.URL) (string, error) {
	host, err := base64.StdEncoding.DecodeString(server.Host)
	if err != nil {
		return "", fmt.Errorf("decoding alias server: %w", err)
	}

	return string(host), nil
}
