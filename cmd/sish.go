package cmd

import (
	"fmt"
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	longCommandInfo = `sish is a command line utility that implements an SSH server 
that can handle HTTP(S)/WS(S)/TCP multiplexing and forwarding.
It can handle multiple vhosting and reverse tunneling.`
)

var (
	// Version describes the version of the current build
	Version = "dev"

	// Commit describes the commit of the current build
	Commit = "none"

	// Date describes the date of the current build
	Date = "unknown"

	configFile string

	rootCmd = &cobra.Command{
		Use:     "sish",
		Short:   "The sish command initializes and runs the sish ssh multiplexer",
		Long:    longCommandInfo,
		Run:     runCommand,
		Version: Version,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetVersionTemplate(fmt.Sprintf("Version: %v\nCommit: %v\nDate: %v\n", Version, Commit, Date))

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yml", "Config file")
	rootCmd.PersistentFlags().StringP("ssh-addr", "a", "localhost:2222", "The address to listen for SSH connections")
	rootCmd.PersistentFlags().StringP("http-addr", "i", "localhost:80", "The address to listen for HTTP connections")
	rootCmd.PersistentFlags().StringP("https-addr", "t", "localhost:443", "The address to listen for HTTPS connections")
	rootCmd.PersistentFlags().StringP("redirect-root-location", "r", "https://github.com/antoniomika/sish", "Where to redirect the root domain to")
	rootCmd.PersistentFlags().StringP("cert-dir", "s", "ssl/", "The location of pem files for HTTPS (fullchain.pem and privkey.pem)")
	rootCmd.PersistentFlags().StringP("domain", "d", "ssi.sh", "The domain for HTTP(S) multiplexing")
	rootCmd.PersistentFlags().StringP("banned-subdomains", "b", "localhost", "A comma separated list of banned subdomains")
	rootCmd.PersistentFlags().StringP("banned-ips", "x", "", "A comma separated list of banned ips")
	rootCmd.PersistentFlags().StringP("banned-countries", "o", "", "A comma separated list of banned countries")
	rootCmd.PersistentFlags().StringP("whitelisted-ips", "w", "", "A comma separated list of whitelisted ips")
	rootCmd.PersistentFlags().StringP("whitelisted-countries", "y", "", "A comma separated list of whitelisted countries")
	rootCmd.PersistentFlags().StringP("privkey-passphrase", "p", "S3Cr3tP4$$phrAsE", "Passphrase to use for the server private key")
	rootCmd.PersistentFlags().StringP("privkey-location", "l", "keys/ssh_key", "SSH server private key")
	rootCmd.PersistentFlags().StringP("auth-password", "u", "S3Cr3tP4$$W0rD", "Password to use for password auth")
	rootCmd.PersistentFlags().StringP("auth-keys-dir", "k", "pubkeys/", "Directory for public keys for pubkey auth")
	rootCmd.PersistentFlags().StringP("bind-range", "n", "0,1024-65535", "Ports that are allowed to be bound")
	rootCmd.PersistentFlags().StringP("proxy-protocol-version", "q", "1", "What version of the proxy protocol to use.\nCan either be 1, 2, or userdefined. If userdefined, the user needs to add a command to SSH called proxyproto:version (ie proxyproto:1)")
	rootCmd.PersistentFlags().StringP("admin-token", "j", "S3Cr3tP4$$W0rD", "The token to use for admin access")
	rootCmd.PersistentFlags().StringP("service-console-token", "m", "", "The token to use for service access. Auto generated if empty.")

	rootCmd.PersistentFlags().BoolP("append-user-to-subdomain", "", false, "Whether or not to append the user to the subdomain")
	rootCmd.PersistentFlags().BoolP("admin-enabled", "", false, "Whether or not to enable the admin console")
	rootCmd.PersistentFlags().BoolP("service-console-enabled", "", false, "Whether or not to enable the admin console for each service and send the info to users")
	rootCmd.PersistentFlags().BoolP("force-random-subdomain", "", true, "Whether or not to force a random subdomain")
	rootCmd.PersistentFlags().BoolP("verify-origin", "", true, "Whether or not to verify origin on websocket connection")
	rootCmd.PersistentFlags().BoolP("verify-ssl", "", true, "Whether or not to verify SSL on proxy connection")
	rootCmd.PersistentFlags().BoolP("https-enabled", "", false, "Whether or not to listen for HTTPS connections")
	rootCmd.PersistentFlags().BoolP("redirect-root", "", true, "Whether or not to redirect the root domain")
	rootCmd.PersistentFlags().BoolP("use-geodb", "", false, "Whether or not to use the maxmind geodb")
	rootCmd.PersistentFlags().BoolP("authentication-enabled", "", false, "Whether or not to require auth on the SSH service")
	rootCmd.PersistentFlags().BoolP("cleanup-unbound", "", true, "Whether or not to cleanup unbound (forwarded) SSH connections")
	rootCmd.PersistentFlags().BoolP("bind-random", "", true, "Bind ports randomly (OS chooses)")
	rootCmd.PersistentFlags().BoolP("proxy-protocol-enabled", "", false, "Whether or not to enable the use of the proxy protocol")
	rootCmd.PersistentFlags().BoolP("debug", "", false, "Whether or not to print debug information")
	rootCmd.PersistentFlags().BoolP("version", "", false, "Print version and exit")
	rootCmd.PersistentFlags().BoolP("tcp-alias", "", false, "Whether or not to allow the use of TCP aliasing")
	rootCmd.PersistentFlags().BoolP("log-to-client", "", false, "Whether or not to log http requests to the client")

	rootCmd.PersistentFlags().IntP("http-port-override", "", 0, "The port to use for http command output")
	rootCmd.PersistentFlags().IntP("https-port-override", "", 0, "The port to use for https command output")
	rootCmd.PersistentFlags().IntP("max-subdomain-len", "", 3, "The length of the random subdomain to generate")
	rootCmd.PersistentFlags().IntP("connection-idle-timeout", "", 5, "Number of seconds to wait for activity before closing a connection")
}

func initConfig() {
	viper.SetConfigFile(configFile)

	err := viper.BindPFlags(rootCmd.PersistentFlags())
	if err != nil {
		log.Println("unable to bind pflags:", err)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}

	viper.WatchConfig()

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Reloaded configuration file.")
	})
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func runCommand(cmd *cobra.Command, args []string) {
	// log.Printf("%+v", viper.AllSettings())
	// log.Println(cmd, args)
}
