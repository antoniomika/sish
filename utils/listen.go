package utils

import (
	"net"
	"strings"

	"github.com/antoniomika/multilistener"
)

// Listen uses the multilistener package to generate a net.Listener that uses multiple addresses.
func Listen(addresses string) (net.Listener, error) {
	listeners := map[string][]string{}
	addressList := strings.Split(addresses, ",")

	for _, address := range addressList {
		addressSplit := strings.Split(address, "://")
		if len(addressSplit) != 2 {
			if _, ok := listeners["tcp"]; !ok {
				listeners["tcp"] = []string{}
			}
			listeners["tcp"] = append(listeners["tcp"], address)
			continue
		}

		if _, ok := listeners[addressSplit[0]]; !ok {
			listeners[addressSplit[0]] = []string{}
		}
		listeners[addressSplit[0]] = append(listeners[addressSplit[0]], addressSplit[1])
	}

	return multilistener.Listen(listeners)
}

// ParseAddress parse a list of addresses into a host, port, err split.
func ParseAddress(addresses string) (string, string, error) {
	addressList := strings.Split(addresses, ",")
	addressSplit := strings.Split(addressList[0], "://")

	address := addressSplit[0]
	if len(addressList) == 2 {
		address = addressSplit[1]
	}
	return net.SplitHostPort(address)
}
