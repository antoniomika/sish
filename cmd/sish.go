package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/antoniomika/sish/sshmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		Long:    "sish is a command line utility that implements an SSH server that can handle HTTP(S)/WS(S)/TCP multiplexing and forwarding.\nIt can handle multiple vhosting and reverse tunneling endpoints for a large number of clients.",
		Run:     runCommand,
		Version: Version,
	}
)

type logWriter struct {
	TimeFmt string
}

func (w logWriter) Write(bytes []byte) (int, error) {
	return fmt.Printf("%v | %s", time.Now().Format(w.TimeFmt), string(bytes))
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetVersionTemplate(fmt.Sprintf("Version: %v\nCommit: %v\nDate: %v\n", Version, Commit, Date))

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yml", "Config file")

	rootCmd.PersistentFlags().StringP("ssh-address", "a", "localhost:2222", "The address to listen for SSH connections")
	rootCmd.PersistentFlags().StringP("http-address", "i", "localhost:80", "The address to listen for HTTP connections")
	rootCmd.PersistentFlags().StringP("https-address", "t", "localhost:443", "The address to listen for HTTPS connections")
	rootCmd.PersistentFlags().StringP("redirect-root-location", "r", "https://github.com/antoniomika/sish", "The location to redirect requests to the root domain\nto instead of responding with a 404")
	rootCmd.PersistentFlags().StringP("https-certificate-directory", "s", "deploy/ssl/", "The directory containing HTTPS certificate files (fullchain.pem and privkey.pem)")
	rootCmd.PersistentFlags().StringP("domain", "d", "ssi.sh", "The root domain for HTTP(S) multiplexing that will be appended to subdomains")
	rootCmd.PersistentFlags().StringP("banned-subdomains", "b", "localhost", "A comma separated list of banned subdomains that users are unable to bind")
	rootCmd.PersistentFlags().StringP("banned-ips", "x", "", "A comma separated list of banned ips that are unable to access the service. Applies to HTTP, TCP, and SSH connections")
	rootCmd.PersistentFlags().StringP("banned-countries", "o", "", "A comma separated list of banned countries. Applies to HTTP, TCP, and SSH connections")
	rootCmd.PersistentFlags().StringP("whitelisted-ips", "w", "", "A comma separated list of whitelisted ips. Applies to HTTP, TCP, and SSH connections")
	rootCmd.PersistentFlags().StringP("whitelisted-countries", "y", "", "A comma separated list of whitelisted countries. Applies to HTTP, TCP, and SSH connections")
	rootCmd.PersistentFlags().StringP("private-key-passphrase", "p", "S3Cr3tP4$$phrAsE", "Passphrase to use to encrypt the server private key")
	rootCmd.PersistentFlags().StringP("private-key-location", "l", "deploy/keys/ssh_key", "The location of the SSH server private key. sish will create a private key here if\nit doesn't exist using the --private-key-passphrase to encrypt it if supplied")
	rootCmd.PersistentFlags().StringP("authentication-password", "u", "S3Cr3tP4$$W0rD", "Password to use for ssh server password authentication")
	rootCmd.PersistentFlags().StringP("authentication-keys-directory", "k", "deploy/pubkeys/", "Directory where public keys for public key authentication are stored.\nsish will watch this directory and automatically load new keys and remove keys\nfrom the authentication list")
	rootCmd.PersistentFlags().StringP("port-bind-range", "n", "0,1024-65535", "Ports or port ranges that sish will allow to be bound when a user attempts to use TCP forwarding")
	rootCmd.PersistentFlags().StringP("proxy-protocol-version", "q", "1", "What version of the proxy protocol to use. Can either be 1, 2, or userdefined.\nIf userdefined, the user needs to add a command to SSH called proxyproto:version (ie proxyproto:1)")
	rootCmd.PersistentFlags().StringP("admin-console-token", "j", "S3Cr3tP4$$W0rD", "The token to use for admin console access if it's enabled")
	rootCmd.PersistentFlags().StringP("service-console-token", "m", "", "The token to use for service console access. Auto generated if empty for each connected tunnel")
	rootCmd.PersistentFlags().StringP("append-user-to-subdomain-separator", "", "-", "The token to use for separating username and subdomain selection in a virtualhost")
	rootCmd.PersistentFlags().StringP("time-format", "", "2006/01/02 - 15:04:05", "The time format to use for both HTTP and general log messages.")

	rootCmd.PersistentFlags().BoolP("bind-random-subdomains", "", true, "Force bound HTTP tunnels to use random subdomains instead of user provided ones")
	rootCmd.PersistentFlags().BoolP("verify-origin", "", true, "Verify the request origin on websocket connections")
	rootCmd.PersistentFlags().BoolP("verify-ssl", "", true, "Verify SSL certificates made on proxied HTTP connections")
	rootCmd.PersistentFlags().BoolP("cleanup-unbound", "", true, "Cleanup unbound (unforwarded) SSH connections after a set timeout")
	rootCmd.PersistentFlags().BoolP("bind-random-ports", "", true, "Force TCP tunnels to bind a random port, where the kernel will randomly assign it")
	rootCmd.PersistentFlags().BoolP("append-user-to-subdomain", "", false, "Append the SSH user to the subdomain. This is useful in multitenant environments")
	rootCmd.PersistentFlags().BoolP("debug", "", false, "Enable debugging information")
	rootCmd.PersistentFlags().BoolP("ping-client", "", true, "Send ping requests to the underlying SSH client.\nThis is useful to ensure that SSH connections are kept open or close cleanly")
	rootCmd.PersistentFlags().BoolP("geodb", "", false, "Use a geodb to verify country IP address association for IP filtering")
	rootCmd.PersistentFlags().BoolP("authentication", "", false, "Require authentication for the SSH service")
	rootCmd.PersistentFlags().BoolP("proxy-protocol", "", false, "Use the proxy-protocol while proxying connections in order to pass-on IP address and port information")
	rootCmd.PersistentFlags().BoolP("https", "", false, "Listen for HTTPS connections. Requires a correct --https-certificate-directory")
	rootCmd.PersistentFlags().BoolP("redirect-root", "", true, "Redirect the root domain to the location defined in --redirect-root-location")
	rootCmd.PersistentFlags().BoolP("admin-console", "", false, "Enable the admin console accessible at http(s)://domain/_sish/console?x-authorization=admin-console-token")
	rootCmd.PersistentFlags().BoolP("service-console", "", false, "Enable the service console for each service and send the info to connected clients")
	rootCmd.PersistentFlags().BoolP("tcp-aliases", "", false, "Enable the use of TCP aliasing")
	rootCmd.PersistentFlags().BoolP("log-to-client", "", false, "Enable logging HTTP and TCP requests to the client")
	rootCmd.PersistentFlags().BoolP("idle-connection", "", true, "Enable connection idle timeouts for reads and writes")

	rootCmd.PersistentFlags().IntP("http-port-override", "", 0, "The port to use for http command output. This does not effect ports used for connecting, it's for cosmetic use only")
	rootCmd.PersistentFlags().IntP("https-port-override", "", 0, "The port to use for https command output. This does not effect ports used for connecting, it's for cosmetic use only")
	rootCmd.PersistentFlags().IntP("bind-random-subdomains-length", "", 3, "The length of the random subdomain to generate if a subdomain is unavailable or if random subdomains are enforced")

	rootCmd.PersistentFlags().DurationP("idle-connection-timeout", "", 5*time.Second, "Duration to wait for activity before closing a connection for all reads and writes")
	rootCmd.PersistentFlags().DurationP("ping-client-interval", "", 5*time.Second, "Duration representing an interval to ping a client to ensure it is up")
	rootCmd.PersistentFlags().DurationP("ping-client-timeout", "", 5*time.Second, "Duration to wait for activity before closing a connection after sending a ping to a client")
	rootCmd.PersistentFlags().DurationP("cleanup-unbound-timeout", "", 5*time.Second, "Duration to wait before cleaning up an unbound (unforwarded) connection")
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

		log.SetFlags(0)
		log.SetOutput(logWriter{
			TimeFmt: viper.GetString("time-format"),
		})
	})

	log.SetFlags(0)
	log.SetOutput(logWriter{
		TimeFmt: viper.GetString("time-format"),
	})

	utils.Setup()
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func runCommand(cmd *cobra.Command, args []string) {
	sshmuxer.Start()
}
