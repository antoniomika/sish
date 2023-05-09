package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// RoundTripper returns the specific handler for unix connections. This
// will allow us to use our created sockets cleanly.
func RoundTripper() *http.Transport {
	dialer := func(network, addr string) (net.Conn, error) {
		realAddr, err := base64.StdEncoding.DecodeString(strings.Split(addr, ":")[0])
		if err != nil {
			log.Println("Unable to parse socket:", err)
		}

		return net.Dial("unix", string(realAddr))
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !viper.GetBool("verify-ssl"),
	}

	return &http.Transport{
		Dial:            dialer,
		TLSClientConfig: tlsConfig,
	}
}

// ResponseModifier implements a response modifier for the specified request.
// We don't actually modify any requests, but we do want to record the request
// so we can send it to the web console.
func ResponseModifier(state *utils.State, hostname string, reqBody []byte, c *gin.Context, currentListener *utils.HTTPHolder) func(*http.Response) error {
	return func(response *http.Response) error {
		if viper.GetBool("admin-console") || viper.GetBool("service-console") {
			var err error
			var resBody []byte

			if viper.GetInt64("service-console-max-content-length") == -1 || (viper.GetInt64("service-console-max-content-length") > -1 && response.ContentLength > -1 && response.ContentLength < viper.GetInt64("service-console-max-content-length")) {
				resBody, err = io.ReadAll(response.Body)
				if err != nil {
					log.Println("Error reading response body:", err)
				}
			}

			if resBody != nil {
				contentLength := int64(len(resBody))
				currentListener.History.ResponseContentLength += contentLength
				response.Body = io.NopCloser(bytes.NewBuffer(resBody))

				if response.Header.Get("Content-Encoding") == "gzip" {
					gzData := bytes.NewBuffer(resBody)
					gzReader, err := gzip.NewReader(gzData)
					if err != nil {
						log.Println("Error reading gzip data:", err)
					}

					resBody, err = io.ReadAll(gzReader)
					if err != nil {
						log.Println("Error reading gzip data:", err)
					}
				}
			} else {
				resBody = []byte("{\"_sish_status\": false, \"_sish_message\": \"response body size exceeds limit for service console\"}")
			}

			startTime := c.GetTime("startTime")

			requestHeaders := c.Request.Header.Clone()
			requestHeaders.Add("Host", hostname)

			data := map[string]any{
				"startTime":          startTime,
				"startTimePretty":    startTime.Format(viper.GetString("time-format")),
				"requestIP":          c.ClientIP(),
				"requestMethod":      c.Request.Method,
				"requestUrl":         c.Request.URL,
				"originalRequestURI": c.GetString("originalURI"),
				"requestHeaders":     requestHeaders,
				"requestBody":        base64.StdEncoding.EncodeToString(reqBody),
				"responseHeaders":    response.Header,
				"responseBody":       base64.StdEncoding.EncodeToString(resBody),
			}

			if response.Request != nil {
				hostLocation, err := base64.StdEncoding.DecodeString(response.Request.URL.Host)
				if err != nil {
					log.Println("Error loading proxy info from request", err)
				}

				c.Set("proxySocket", string(hostLocation))
			}

			c.Set("broadcastRoute", currentListener.HTTPUrl.String())
			c.Set("broadcastData", data)
		}

		return nil
	}
}
