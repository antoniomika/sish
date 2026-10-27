// Package httpmuxer handles all of the HTTP connections made
// to sish. This implements the http multiplexing necessary for
// sish's core feature.
package httpmuxer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/antoniomika/sish/templates"
	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"

	"github.com/caddyserver/certmagic"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"

	"github.com/gin-gonic/gin"
)

// abortedKey is the request context key for the flag recoverAbort sets.
type abortedKey struct{}

// recoverAbort stops the http.ErrAbortHandler the proxy raises for a cut-off
// response, so the access log line and the console broadcast still happen,
// and flags the request for reraiseAbort. Other panics go on to recoverPanic.
func recoverAbort(c *gin.Context) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}

		if err, ok := rec.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
			panic(rec)
		}

		if aborted, ok := c.Request.Context().Value(abortedKey{}).(*bool); ok {
			*aborted = true
		}

		c.Abort()
	}()

	c.Next()
}

// recordErrors keeps the request's error messages, without gin's numbering, for
// the request log.
func recordErrors(c *gin.Context) {
	c.Next()

	if len(c.Errors) > 0 {
		c.Set("requestErrors", c.Errors.Errors())
	}
}

// recoverPanic logs a panic from a request handler and fails the request.
func recoverPanic(c *gin.Context, rec any) {
	slog.Error(
		"panic recovered",
		"err", rec,
		"stack", string(debug.Stack()),
	)

	c.AbortWithStatus(http.StatusInternalServerError)
}

// reraiseAbort serves engine and raises http.ErrAbortHandler again for a
// request recoverAbort flagged, so net/http closes the connection instead of
// ending the response as complete. Raising it out here lets gin finish the
// request and return its context to the pool.
func reraiseAbort(engine http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aborted := false

		engine.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), abortedKey{}, &aborted)))

		if aborted {
			panic(http.ErrAbortHandler)
		}
	})
}

// Start initializes the HTTP service.
func Start(state *utils.State) {
	releaseMode := gin.ReleaseMode
	if viper.GetBool("debug") {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)
	// Requests are logged through slog in the formatter below.
	gin.DefaultWriter = io.Discard
	gin.DebugPrintFunc = func(format string, values ...any) {
		slog.Debug(
			"gin",
			"message", strings.TrimSpace(fmt.Sprintf(format, values...)),
		)
	}
	gin.ForceConsoleColor()

	r := gin.New()

	if viper.GetBool("load-templates") {
		if dir := viper.GetString("load-templates-directory"); dir != "" {
			r.LoadHTMLGlob(dir)
		} else {
			r.SetHTMLTemplate(template.Must(template.ParseFS(templates.FS, "*.tmpl")))
		}
	}

	r.Use(func(c *gin.Context) {
		// startTime is used for calculating latencies.
		c.Set("startTime", time.Now())

		// Here is where we check whether or not an IP is blocked.
		clientIPAddr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		clientIPAddrBlocked := state.IPFilter.Blocked(clientIPAddr)
		cClientIP := c.ClientIP()
		cClientIPBlocked := state.IPFilter.Blocked(cClientIP)

		if clientIPAddrBlocked || cClientIPBlocked || err != nil {
			status := http.StatusForbidden
			c.AbortWithStatus(status)
			slog.Debug(
				"aborting with status",
				"status", status,
				"remoteAddrBlocked", clientIPAddrBlocked,
				"remoteAddr", clientIPAddr,
				"clientIPBlocked", cClientIPBlocked,
				"clientIP", cClientIP,
			)
			return
		}
		c.Next()
	}, gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Here is the logger we use to format each incoming request.
		var statusColor, methodColor, resetColor string
		if param.IsOutputColor() {
			statusColor = param.StatusCodeColor()
			methodColor = param.MethodColor()
			resetColor = param.ResetColor()
		}

		if param.Latency > time.Minute {
			// Truncate in a golang < 1.8 safe way
			param.Latency = param.Latency - param.Latency%time.Second
		}

		originalHost := param.Keys["originalHost"].(string)

		// Tunnels without a configured service console token get their own.
		var routeToken, tunnelId string
		if holder, ok := param.Keys["httpHolder"].(*utils.HTTPHolder); ok && holder != nil {
			routeToken, _ = state.Console.RouteToken(holder.HTTPUrl.String())
			tunnelId = holder.TunnelId()
		}

		originalURI := redactURI(param.Keys["originalURI"].(string), viper.GetString("admin-console-token"), viper.GetString("service-console-token"), routeToken)

		logLine := fmt.Sprintf("%v | %s |%s %3d %s| %13v | %15s |%s %-7s %s %s\n%s",
			param.TimeStamp.Format(viper.GetString("time-format")),
			originalHost,
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			originalURI,
			param.ErrorMessage,
		)

		connectionType := "http"
		if param.Request.TLS != nil {
			connectionType = "https"
		}

		requestAttrs := []any{
			"status", param.StatusCode,
			"method", param.Method,
			"url", originalHost + originalURI,
			"latency", param.Latency,
			"clientIP", param.ClientIP,
			"tunnelType", "http",
			"tunnelId", tunnelId,
			"connectionType", connectionType,
		}

		if requestErrors, ok := param.Keys["requestErrors"].([]string); ok {
			requestAttrs = append(requestAttrs, "err", strings.Join(requestErrors, "; "))
		}

		slog.Info("http request", requestAttrs...)

		if viper.GetBool("log-to-client") && param.Keys["httpHolder"] != nil {
			currentListener := param.Keys["httpHolder"].(*utils.HTTPHolder)

			if currentListener != nil {
				proxySock, _ := param.Keys["proxySocket"].(string)
				sshConnTmp, ok := currentListener.SSHConnections.Load(proxySock)
				if ok {
					sshConn := sshConnTmp
					sshConn.SendLog(slog.LevelInfo, strings.TrimSpace(logLine), "http request", requestAttrs...)
				} else {
					currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
						sshConn.SendLog(slog.LevelInfo, strings.TrimSpace(logLine), "http request", requestAttrs...)
						return true
					})
				}
			}
		}

		routeInfo, routeOk := param.Keys["broadcastRoute"].(string)
		routeData, dataOk := param.Keys["broadcastData"].(map[string]any)

		if routeOk && dataOk {
			roundTime := 10 * time.Microsecond
			if param.Latency > time.Second {
				roundTime = 10 * time.Millisecond
			}

			routeData["currentTime"] = param.TimeStamp.Format(viper.GetString("time-format"))
			routeData["requestTime"] = param.Latency.Round(roundTime).String()
			routeData["responseCode"] = param.StatusCode
			routeData["responseStatus"] = fmt.Sprintf("%d %s", param.StatusCode, http.StatusText(param.StatusCode))

			recordRequestBody(param.Keys, routeData)

			state.Console.BroadcastRoute(routeInfo, routeData)
		}

		return logLine
	}), recordErrors, gin.CustomRecoveryWithWriter(nil, recoverPanic), recoverAbort, func(c *gin.Context) {
		c.Set("originalHost", c.Request.Host)
		c.Set("originalURI", c.Request.RequestURI)
		c.Set("originalPath", c.Request.URL.Path)
		c.Set("originalRawPath", c.Request.URL.RawPath)

		hostSplit := strings.Split(c.Request.Host, ":")
		if strings.Contains(c.Request.Host, "[") && strings.Contains(c.Request.Host, "]") {
			hostSplit = strings.Split(c.Request.Host, "]:")
			if len(hostSplit) > 1 {
				hostSplit[0] = hostSplit[0] + "]"
			}
		}

		hostname := hostSplit[0]
		hostIsRoot := hostname == viper.GetString("domain")

		if viper.GetBool("admin-console") && hostIsRoot && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest("", hostIsRoot, c)
			return
		}

		var currentListener *utils.HTTPHolder

		requestUsername, requestPassword, _ := c.Request.BasicAuth()
		authNeeded := true

		// Loop for checking if there's a listener with auth set (most specific)
		state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
			parsedPassword, _ := locationListener.HTTPUrl.User.Password()

			if hostname == locationListener.HTTPUrl.Host && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
				credsNeeded := locationListener.HTTPUrl.User.Username() != "" && parsedPassword != ""
				credsMatch := requestUsername == locationListener.HTTPUrl.User.Username() && requestPassword == parsedPassword

				if credsNeeded {
					currentListener = locationListener

					if credsMatch {
						authNeeded = false
						return false
					}
				}
			}

			return true
		})

		// Loop for checking if there's a listener with the exact host and path prefix set (next most specific)
		if currentListener == nil {
			state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
				if hostname == locationListener.HTTPUrl.Host && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
					currentListener = locationListener
					authNeeded = false
					return false
				}

				return true
			})
		}

		// Loop for checking if there's a wildcard listener with the host and path prefix set (least most specific)
		if currentListener == nil {
			state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
				if utils.MatchesWildcardHost(hostname, locationListener.HTTPUrl.Host) && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
					currentListener = locationListener
					authNeeded = false
					return false
				}

				return true
			})
		}

		if currentListener == nil && hostIsRoot {
			if viper.GetBool("redirect-root") && !strings.HasPrefix(c.Request.URL.Path, "/favicon.ico") {
				c.Redirect(http.StatusFound, viper.GetString("redirect-root-location"))
				return
			}

			status := http.StatusNotFound
			c.AbortWithStatus(status)
			slog.Debug(
				"aborting with status",
				"status", status,
			)
			return
		}

		if currentListener == nil {
			_ = c.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", hostname))
			return
		}

		c.Set("httpHolder", currentListener)

		if authNeeded {
			c.Header("WWW-Authenticate", "Basic realm=\"sish\"")
			status := http.StatusUnauthorized
			c.AbortWithStatus(status)
			slog.Debug(
				"aborting with status",
				"status", status,
			)
			return
		}

		stripPath := viper.GetBool("strip-http-path")
		forceHTTPS := viper.GetBool("force-all-https")

		currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
			newHost := sshConn.HostHeader
			forceHTTPS = forceHTTPS || sshConn.ForceHTTPS

			if sshConn.StripPath != viper.GetBool("strip-http-path") {
				stripPath = sshConn.StripPath
			}

			if newHost == "" {
				return true
			}

			if len(hostSplit) > 1 {
				newHost = fmt.Sprintf("%s:%s", newHost, hostSplit[1])
			}

			c.Request.Host = newHost
			return false
		})

		if forceHTTPS && c.Request.TLS == nil && viper.GetBool("https") {
			c.Request.URL.Scheme = "https"
			c.Request.URL.Host = hostname
			if state.Ports.HTTPSPort != 443 {
				c.Request.URL.Host = fmt.Sprintf("%s:%d", hostname, state.Ports.HTTPSPort)
			}

			c.Redirect(http.StatusFound, c.Request.URL.String())
			return
		}

		if viper.GetBool("strip-http-path") && stripPath {
			c.Request.RequestURI = strings.TrimPrefix(c.Request.RequestURI, currentListener.HTTPUrl.Path)
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, currentListener.HTTPUrl.Path)
			c.Request.URL.RawPath = strings.TrimPrefix(c.Request.URL.RawPath, currentListener.HTTPUrl.Path)
		}

		if viper.GetBool("rewrite-host-header") {
			currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
				newHost := sshConn.HostHeader

				if newHost == "" {
					return true
				}

				if len(hostSplit) > 1 {
					newHost = fmt.Sprintf("%s:%s", newHost, hostSplit[1])
				}

				c.Request.Host = newHost
				return false
			})
		}

		if (viper.GetBool("admin-console") || viper.GetBool("service-console")) && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest(currentListener.HTTPUrl.String(), hostIsRoot, c)
			return
		}

		// Only the console uses the body, and reading it holds the whole
		// request in memory before forwarding.
		var reqBody []byte
		if consoleEnabled() {
			body, err := readRequestBody(c)
			if err != nil {
				slog.Error(
					"error reading request body",
					"err", err,
				)
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			reqBody = body
		}

		c.Request = withPublicHost(c.Request, c.GetString("originalHost"))
		c.Request = withResponseModifier(c.Request, ResponseModifier(state, hostname, reqBody, c, currentListener))

		gin.WrapH(currentListener.Balancer)(c)
	})

	handler := reraiseAbort(r)

	var acmeIssuer *certmagic.ACMEIssuer = nil

	// If HTTPS is enabled, setup certmagic to allow us to provision HTTPS certs on the fly.
	// You can use sish without a wildcard cert, but you really should. If you get a lot of clients
	// with many random subdomains, you'll burn through your Let's Encrypt quota. Be careful!
	if viper.GetBool("https") {
		certmagic.Default.Storage = &certmagic.FileStorage{
			Path: filepath.Join(viper.GetString("https-certificate-directory"), "certmagic"),
		}
		certmagic.Default.Logger = utils.ZapLogger()
		certmagic.DefaultACME.Logger = certmagic.Default.Logger

		certManager := certmagic.NewDefault()

		acmeIssuer = certmagic.NewACMEIssuer(certManager, certmagic.DefaultACME)

		acmeIssuer.Agreed = viper.GetBool("https-ondemand-certificate-accept-terms")
		acmeIssuer.Email = viper.GetString("https-ondemand-certificate-email")

		certManager.Issuers = []certmagic.Issuer{acmeIssuer}

		certManager.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if !viper.GetBool("https-ondemand-certificate") {
					return fmt.Errorf("ondemand certificate retrieval is not enabled")
				}

				ok := name == viper.GetString("domain")

				if !ok {
					state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
						if name == locationListener.HTTPUrl.Host || utils.MatchesWildcardHost(name, locationListener.HTTPUrl.Host) {
							ok = true
							return false
						}

						return true
					})
				}

				if !ok {
					return fmt.Errorf("cannot find connection for host: %s", name)
				}

				slog.Info(
					"requesting certificate for host",
					"host", name,
				)
				return nil
			},
		}

		utils.WatchCerts(certManager)

		tlsConfig := certManager.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		httpsServer := newServer(viper.GetString("https-address"), handler)
		httpsServer.TLSConfig = tlsConfig

		go func() {
			// We'll replace this with a custom listener
			// That listener will then check the hostname of the request and choose the connection to send it to
			portListener, err := utils.Listen(httpsServer.Addr)
			if err != nil {
				utils.Fatal(
					"unable to listen",
					"address", httpsServer.Addr,
					"err", err,
				)
			}

			pListener := portListener

			if viper.GetBool("proxy-protocol-listener") {
				hListener := &proxyproto.Listener{
					Listener: portListener,
				}

				utils.LoadProxyProtoConfig(hListener)
				pListener = hListener
			}

			httpsListener := pListener

			var tH *utils.TCPHolder

			if viper.GetBool("sni-proxy-https") {
				tH = &utils.TCPHolder{
					TCPHost:        httpsServer.Addr,
					SSHConnections: syncmap.New[string, *utils.SSHConnection](),
					Balancers:      syncmap.New[string, *roundrobin.RoundRobin](),
					SNIProxy:       true,
					NoHandle:       true,
				}

				balancer, err := roundrobin.New(nil)
				if err != nil {
					utils.Fatal(
						"unable to initialize tcp balancer",
						"err", err,
					)
				}

				err = balancer.UpsertServer(&url.URL{
					Host: base64.StdEncoding.EncodeToString([]byte("_sish_https_root")),
				})

				if err != nil {
					utils.Fatal(
						"unable to add empty balancer server",
						"err", err,
					)
				}

				tH.Balancers.Store("", balancer)

				httpsListener = &proxyListener{
					Listener: pListener,
					Holder:   tH,
					State:    state,
				}
			}

			if tH != nil {
				tH.Listener = httpsListener

				state.Listeners.Store(httpsServer.Addr, httpsListener)
				state.TCPListeners.Store(httpsServer.Addr, tH)
			}

			defer func() {
				err := httpsListener.Close()
				if err != nil {
					slog.Error(
						"error closing https listener",
						"err", err,
					)
				}
			}()

			err = httpsServer.ServeTLS(httpsListener, "", "")
			utils.Fatal(
				"https server stopped",
				"err", err,
			)
		}()
	}

	httpServer := newServer(viper.GetString("http-address"), handler)
	if acmeIssuer != nil {
		httpServer.Handler = acmeIssuer.HTTPChallengeHandler(handler)
	}

	var httpListener net.Listener

	l, err := utils.Listen(httpServer.Addr)
	if err != nil {
		utils.Fatal(
			"unable to listen",
			"address", httpServer.Addr,
			"err", err,
		)
	}

	if viper.GetBool("proxy-protocol-listener") {
		hListener := &proxyproto.Listener{
			Listener: l,
		}

		utils.LoadProxyProtoConfig(hListener)
		httpListener = hListener
	} else {
		httpListener = l
	}

	defer func() {
		err := httpListener.Close()
		if err != nil {
			slog.Error(
				"error closing http listener",
				"err", err,
			)
		}
	}()

	err = httpServer.Serve(httpListener)
	utils.Fatal(
		"http server stopped",
		"err", err,
	)
}

// newServer returns a server for visitor traffic. Read and write timeouts stay
// unset so long transfers and upgraded connections aren't cut off.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: viper.GetDuration("http-read-header-timeout"),
		IdleTimeout:       viper.GetDuration("http-idle-timeout"),
	}
}

// redactURI hides console tokens in uri before it is logged. Each of tokens is
// hidden wherever it appears, and so is any x-authorization parameter, which
// covers tokens that are wrong or belong to a route that has since closed.
func redactURI(uri string, tokens ...string) string {
	for _, token := range tokens {
		if token != "" {
			uri = strings.ReplaceAll(uri, token, "[REDACTED]")
		}
	}

	path, query, ok := strings.Cut(uri, "?")
	if !ok {
		return uri
	}

	params := strings.Split(query, "&")
	for i, param := range params {
		key, _, _ := strings.Cut(param, "=")

		name, err := url.QueryUnescape(key)
		if err != nil {
			name = key
		}

		if name == "x-authorization" {
			params[i] = key + "=[REDACTED]"
		}
	}

	return path + "?" + strings.Join(params, "&")
}
