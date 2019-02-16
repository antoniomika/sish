package main

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/valyala/fasthttp"
)

// ProxyHolder holds proxy and connection info
type ProxyHolder struct {
	ProxyClient *fasthttp.HostClient
}

var (
	green   = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white   = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow  = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red     = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue    = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan    = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset   = string([]byte{27, 91, 48, 109})
)

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return white
	case code >= 400 && code < 500:
		return yellow
	default:
		return red
	}
}

func colorForMethod(method string) string {
	switch method {
	case "GET":
		return blue
	case "POST":
		return cyan
	case "PUT":
		return yellow
	case "DELETE":
		return red
	case "PATCH":
		return green
	case "HEAD":
		return magenta
	case "OPTIONS":
		return white
	default:
		return reset
	}
}

func logReq(ctx *fasthttp.RequestCtx) {
	statusCode := ctx.Response.StatusCode()
	method := string(ctx.Method())
	statusColor := colorForStatus(statusCode)
	methodColor := colorForMethod(method)
	latency := time.Now().Sub(ctx.Time())
	clientIP := ctx.RemoteIP().String()
	path := string(ctx.Path())
	headers := string(ctx.Request.Header.RawHeaders())

	realIP := string(ctx.Request.Header.Peek("x-forwarded-for"))
	if realIP != "" {
		clientIP += ", " + realIP
	}

	log.Printf("|%s %3d %s| %13v | %15s |%s %-7s %s %s\n%s\n", statusColor, statusCode, reset,
		latency,
		clientIP,
		methodColor, method, reset,
		path,
		headers)
}

func startHTTPHandler(state *State) {
	log.Println("Starting server on address:", *httpAddr)
	if err := fasthttp.ListenAndServe(*httpAddr, handler(state)); err != nil {
		log.Fatalf("%sError in ListenAndServe: %s%s", red, err, reset)
	}
}

func handler(state *State) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		hostname := string(ctx.Host())
		loc, ok := state.HTTPListeners.Load(hostname)
		if !ok {
			ctx.Error("cannot find connection for host: "+hostname, fasthttp.StatusNotFound)
			logReq(ctx)
			return
		}

		proxyClient := loc.(*ProxyHolder)
		req := &ctx.Request
		resp := &ctx.Response

		if ctx.Request.Header.ConnectionUpgrade() {
			dstHost := proxyClient.ProxyClient.Addr
			req := &ctx.Request
			uri := req.URI()
			uri.SetHost(dstHost)
			dstConn, err := fasthttp.DialTimeout(dstHost, 5*time.Second)
			if err != nil {
				ctx.Error("error when proxying the request: "+err.Error(), fasthttp.StatusInternalServerError)
				return
			}
			_, err = req.WriteTo(dstConn)
			if err != nil {
				ctx.Error("error when proxying the request: "+err.Error(), fasthttp.StatusInternalServerError)
				return
			}
			ctx.Hijack(func(conn net.Conn) {
				defer dstConn.Close()
				defer conn.Close()
				errc := make(chan error, 2)
				cp := func(dst io.Writer, src io.Reader) {
					_, err := io.Copy(dst, src)
					errc <- err
				}
				go cp(dstConn, conn)
				go cp(conn, dstConn)
				<-errc
			})
		} else {
			if err := proxyClient.ProxyClient.Do(req, resp); err != nil {
				ctx.Error("error when proxying the request: "+err.Error(), fasthttp.StatusInternalServerError)
			}
		}

		defer logReq(ctx)
	}
}
