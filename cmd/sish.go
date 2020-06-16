// Package cmd implements the sish CLI command.
package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/antoniomika/sish/sshmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// Version describes the version of the current build.
	Version = "dev"

	// Commit describes the commit of the current build.
	Commit = "none"

	// Date describes the date of the current build.
	Date = "unknown"

	// configFile holds the location of the config file from CLI flags.
	configFile string

	// rootCmd is the root cobra command.
	rootCmd = &cobra.Command{
		Use:     "sish",
		Short:   "The sish command initializes and runs the sish ssh multiplexer",
		Long:    "sish is a command line utility that implements an SSH server that can handle HTTP(S)/WS(S)/TCP multiplexing, forwarding and load balancing.\nIt can handle multiple vhosting and reverse tunneling endpoints for a large number of clients.",
		Run:     runCommand,
		Version: Version,
	}
)

// init initializes flags used by the root command.
func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetVersionTemplate(fmt.Sprintf("Version: %v\nCommit: %v\nDate: %v\n", Version, Commit, Date))

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yml", "Config file")

	rootCmd.PersistentFlags().StringP("ssh-address", "a", "localhost:2222", "The address to listen for SSH connections")
	rootCmd.PersistentFlags().StringP("http-address", "i", "localhost:80", "The address to listen for HTTP connections")
	rootCmd.PersistentFlags().StringP("https-address", "t", "localhost:443", "The address to listen for HTTPS connections")
	rootCmd.PersistentFlags().StringP("redirect-root-location", "r", "https://github.com/antoniomika/sish", "The location to redirect requests to the root domain\nto instead of responding with a 404")
	rootCmd.PersistentFlags().StringP("https-certificate-directory", "s", "deploy/ssl/", "The directory containing HTTPS certificate files (name.crt and name.key). There can be many crt/key pairs")
	rootCmd.PersistentFlags().StringP("https-ondemand-certificate-email", "", "", "The email to use with Let's Encrypt for cert notifications. Can be left blank")
	rootCmd.PersistentFlags().StringP("domain", "d", "ssi.sh", "The root domain for HTTP(S) multiplexing that will be appended to subdomains")
	rootCmd.PersistentFlags().StringP("banned-subdomains", "b", "localhost", "A comma separated list of banned subdomains that users are unable to bind")
	rootCmd.PersistentFlags().StringP("banned-aliases", "", "", "A comma separated list of banned aliases that users are unable to bind")
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
	rootCmd.PersistentFlags().StringP("proxy-protocol-policy", "", "use", "What to do with the proxy protocol header. Can be use, ignore, reject, or require")
	rootCmd.PersistentFlags().StringP("admin-console-token", "j", "S3Cr3tP4$$W0rD", "The token to use for admin console access if it's enabled")
	rootCmd.PersistentFlags().StringP("service-console-token", "m", "", "The token to use for service console access. Auto generated if empty for each connected tunnel")
	rootCmd.PersistentFlags().StringP("append-user-to-subdomain-separator", "", "-", "The token to use for separating username and subdomain selection in a virtualhost")
	rootCmd.PersistentFlags().StringP("time-format", "", "2006/01/02 - 15:04:05", "The time format to use for both HTTP and general log messages")
	rootCmd.PersistentFlags().StringP("log-to-file-path", "", "/tmp/sish.log", "The file to write log output to")
	rootCmd.PersistentFlags().StringP("bind-hosts", "", "", "A comma separated list of other hosts a user can bind. Requested hosts should be subdomains of a host in this list")
	rootCmd.PersistentFlags().StringP("load-templates-directory", "", "templates/*", "The directory and glob parameter for templates that should be loaded")

	rootCmd.PersistentFlags().BoolP("force-requested-ports", "", false, "Force the ports used to be the one that is requested. Will fail the bind if it exists already")
	rootCmd.PersistentFlags().BoolP("force-requested-aliases", "", false, "Force the aliases used to be the one that is requested. Will fail the bind if it exists already")
	rootCmd.PersistentFlags().BoolP("force-requested-subdomains", "", false, "Force the subdomains used to be the one that is requested. Will fail the bind if it exists already")
	rootCmd.PersistentFlags().BoolP("bind-random-subdomains", "", true, "Force bound HTTP tunnels to use random subdomains instead of user provided ones")
	rootCmd.PersistentFlags().BoolP("bind-random-aliases", "", true, "Force bound alias tunnels to use random aliases instead of user provided ones")
	rootCmd.PersistentFlags().BoolP("verify-ssl", "", true, "Verify SSL certificates made on proxied HTTP connections")
	rootCmd.PersistentFlags().BoolP("verify-dns", "", true, "Verify DNS information for hosts and ensure it matches a connecting users sha256 key fingerprint")
	rootCmd.PersistentFlags().BoolP("cleanup-unbound", "", true, "Cleanup unbound (unforwarded) SSH connections after a set timeout")
	rootCmd.PersistentFlags().BoolP("bind-random-ports", "", true, "Force TCP tunnels to bind a random port, where the kernel will randomly assign it")
	rootCmd.PersistentFlags().BoolP("append-user-to-subdomain", "", false, "Append the SSH user to the subdomain. This is useful in multitenant environments")
	rootCmd.PersistentFlags().BoolP("debug", "", false, "Enable debugging information")
	rootCmd.PersistentFlags().BoolP("ping-client", "", true, "Send ping requests to the underlying SSH client.\nThis is useful to ensure that SSH connections are kept open or close cleanly")
	rootCmd.PersistentFlags().BoolP("geodb", "", false, "Use a geodb to verify country IP address association for IP filtering")
	rootCmd.PersistentFlags().BoolP("authentication", "", false, "Require authentication for the SSH service")
	rootCmd.PersistentFlags().BoolP("proxy-protocol", "", false, "Use the proxy-protocol while proxying connections in order to pass-on IP address and port information")
	rootCmd.PersistentFlags().BoolP("proxy-protocol-use-timeout", "", false, "Use a timeout for the proxy-protocol read")
	rootCmd.PersistentFlags().BoolP("proxy-protocol-listener", "", false, "Use the proxy-protocol to resolve ip addresses from user connections")
	rootCmd.PersistentFlags().BoolP("https", "", false, "Listen for HTTPS connections. Requires a correct --https-certificate-directory")
	rootCmd.PersistentFlags().BoolP("redirect-root", "", true, "Redirect the root domain to the location defined in --redirect-root-location")
	rootCmd.PersistentFlags().BoolP("admin-console", "", false, "Enable the admin console accessible at http(s)://domain/_sish/console?x-authorization=admin-console-token")
	rootCmd.PersistentFlags().BoolP("service-console", "", false, "Enable the service console for each service and send the info to connected clients")
	rootCmd.PersistentFlags().BoolP("tcp-aliases", "", false, "Enable the use of TCP aliasing")
	rootCmd.PersistentFlags().BoolP("log-to-client", "", false, "Enable logging HTTP and TCP requests to the client")
	rootCmd.PersistentFlags().BoolP("idle-connection", "", true, "Enable connection idle timeouts for reads and writes")
	rootCmd.PersistentFlags().BoolP("http-load-balancer", "", false, "Enable the HTTP load balancer (multiple clients can bind the same domain)")
	rootCmd.PersistentFlags().BoolP("tcp-load-balancer", "", false, "Enable the TCP load balancer (multiple clients can bind the same port)")
	rootCmd.PersistentFlags().BoolP("alias-load-balancer", "", false, "Enable the alias load balancer (multiple clients can bind the same alias)")
	rootCmd.PersistentFlags().BoolP("localhost-as-all", "", true, "Enable forcing localhost to mean all interfaces for tcp listeners")
	rootCmd.PersistentFlags().BoolP("log-to-stdout", "", true, "Enable writing log output to stdout")
	rootCmd.PersistentFlags().BoolP("log-to-file", "", false, "Enable writing log output to file, specified by log-to-file-path")
	rootCmd.PersistentFlags().BoolP("log-to-file-compress", "", false, "Enable compressing log output files")
	rootCmd.PersistentFlags().BoolP("https-ondemand-certificate", "", false, "Enable retrieving certificates on demand via Let's Encrypt")
	rootCmd.PersistentFlags().BoolP("https-ondemand-certificate-accept-terms", "", false, "Accept the Let's Encrypt terms")
	rootCmd.PersistentFlags().BoolP("bind-any-host", "", false, "Bind any host when accepting an HTTP listener")
	rootCmd.PersistentFlags().BoolP("load-templates", "", true, "Load HTML templates. This is required for admin/service consoles")

	rootCmd.PersistentFlags().IntP("http-port-override", "", 0, "The port to use for http command output. This does not effect ports used for connecting, it's for cosmetic use only")
	rootCmd.PersistentFlags().IntP("https-port-override", "", 0, "The port to use for https command output. This does not effect ports used for connecting, it's for cosmetic use only")
	rootCmd.PersistentFlags().IntP("bind-random-subdomains-length", "", 3, "The length of the random subdomain to generate if a subdomain is unavailable or if random subdomains are enforced")
	rootCmd.PersistentFlags().IntP("bind-random-aliases-length", "", 3, "The length of the random alias to generate if a alias is unavailable or if random aliases are enforced")
	rootCmd.PersistentFlags().IntP("log-to-file-max-size", "", 500, "The maximum size of outputed log files in megabytes")
	rootCmd.PersistentFlags().IntP("log-to-file-max-backups", "", 3, "The maxium number of rotated logs files to keep")
	rootCmd.PersistentFlags().IntP("log-to-file-max-age", "", 28, "The maxium number of days to store log output in a file")

	rootCmd.PersistentFlags().DurationP("idle-connection-timeout", "", 5*time.Second, "Duration to wait for activity before closing a connection for all reads and writes")
	rootCmd.PersistentFlags().DurationP("ping-client-interval", "", 5*time.Second, "Duration representing an interval to ping a client to ensure it is up")
	rootCmd.PersistentFlags().DurationP("ping-client-timeout", "", 5*time.Second, "Duration to wait for activity before closing a connection after sending a ping to a client")
	rootCmd.PersistentFlags().DurationP("cleanup-unbound-timeout", "", 5*time.Second, "Duration to wait before cleaning up an unbound (unforwarded) connection")
	rootCmd.PersistentFlags().DurationP("proxy-protocol-timeout", "", 200*time.Millisecond, "The duration to wait for the proxy proto header")
}

// initConfig initializes the configuration and loads needed
// values. It initializes logging and other vars.
func initConfig() {
	viper.SetConfigFile(configFile)

	err := viper.BindPFlags(rootCmd.PersistentFlags())
	if err != nil {
		log.Println("Unable to bind pflags:", err)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}

	viper.WatchConfig()

	writers := []io.Writer{}

	if viper.GetBool("log-to-stdout") {
		writers = append(writers, os.Stdout)
	}

	if viper.GetBool("log-to-file") {
		writers = append(writers, &lumberjack.Logger{
			Filename:   viper.GetString("log-to-file-path"),
			MaxSize:    viper.GetInt("log-to-file-max-size"),
			MaxBackups: viper.GetInt("log-to-file-max-backups"),
			MaxAge:     viper.GetInt("log-to-file-max-age"),
			Compress:   viper.GetBool("log-to-file-compress"),
		})
	}

	multiWriter := io.MultiWriter(writers...)

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Reloaded configuration file.")

		log.SetFlags(0)
		log.SetOutput(utils.LogWriter{
			TimeFmt:     viper.GetString("time-format"),
			MultiWriter: multiWriter,
		})

		if viper.GetBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
	})

	log.SetFlags(0)
	log.SetOutput(utils.LogWriter{
		TimeFmt:     viper.GetString("time-format"),
		MultiWriter: multiWriter,
	})

	if viper.GetBool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.SetOutput(multiWriter)

	utils.Setup(multiWriter)
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

// runCommand is used to start the root muxer.
func runCommand(cmd *cobra.Command, args []string) {
	sshmuxer.Start()
}
