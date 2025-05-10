package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
)

// handleAliasListener handles the creation of the aliasHandler
// (or addition for load balancing) and sets up the underlying listeners.
func handleAliasListener(check *channelForwardMsg, stringPort string, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.AliasHolder, *url.URL, string, string, error) {
	validAlias, aH := utils.GetOpenAlias(check.Addr, stringPort, state, sshConn)

	if !strings.HasPrefix(validAlias, check.Addr) && viper.GetBool("force-requested-aliases") || validAlias == "" {
		return nil, nil, "", "", fmt.Errorf("error assigning requested alias to tunnel")
	}

	if aH == nil {
		lb, err := roundrobin.New(nil)

		if err != nil {
			log.Println("Error initializing alias balancer:", err)
			return nil, nil, "", "", err
		}

		aH = &utils.AliasHolder{
			AliasHost:      validAlias,
			SSHConnections: syncmap.New[string, *utils.SSHConnection](),
			Balancer:       lb,
		}

		state.AliasListeners.Store(validAlias, aH)
	}

	aH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host: base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
	}

	err := aH.Balancer.UpsertServer(serverURL)
	if err != nil {
		log.Println("Unable to add server to balancer")
	}

	requestMessages += fmt.Sprintf("%s: %s\r\n", aurora.BgBlue("TCP Alias"), validAlias)
	log.Printf("%s forwarding started: %s -> %s for client: %s\n", aurora.BgBlue("TCP Alias"), validAlias, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

	return aH, serverURL, validAlias, requestMessages, nil
}
