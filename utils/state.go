package utils

import (
	"sync"

	"github.com/jpillora/ipfilter"
)

// State handles overall state
type State struct {
	Console        *WebConsole
	SSHConnections *sync.Map
	Listeners      *sync.Map
	HTTPListeners  *sync.Map
	TCPListeners   *sync.Map
	IPFilter       *ipfilter.IPFilter
}
