package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

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
func ResponseModifier(state *utils.State, hostname string, reqBody []byte, c *gin.Context) func(*http.Response) error {
	return func(response *http.Response) error {
		if viper.GetBool("admin-console") || viper.GetBool("service-console") {
			resBody, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Println("Error reading response for webconsole:", err)
			}

			response.Body = ioutil.NopCloser(bytes.NewBuffer(resBody))

			startTime := c.GetTime("startTime")
			currentTime := time.Now()
			diffTime := currentTime.Sub(startTime)

			roundTime := 10 * time.Microsecond
			if diffTime > time.Second {
				roundTime = 10 * time.Millisecond
			}

			if response.Header.Get("Content-Encoding") == "gzip" {
				gzData := bytes.NewBuffer(resBody)
				gzReader, err := gzip.NewReader(gzData)
				if err != nil {
					log.Println("Error reading gzip data:", err)
				}

				resBody, err = ioutil.ReadAll(gzReader)
				if err != nil {
					log.Println("Error reading gzip data:", err)
				}
			}

			requestHeaders := c.Request.Header.Clone()
			requestHeaders.Add("Host", hostname)

			data, err := json.Marshal(map[string]interface{}{
				"startTime":       startTime,
				"startTimePretty": startTime.Format(viper.GetString("time-format")),
				"currentTime":     currentTime,
				"requestIP":       c.ClientIP(),
				"requestTime":     diffTime.Round(roundTime).String(),
				"requestMethod":   c.Request.Method,
				"requestUrl":      c.Request.URL,
				"requestHeaders":  requestHeaders,
				"requestBody":     base64.StdEncoding.EncodeToString(reqBody),
				"responseHeaders": response.Header,
				"responseCode":    response.StatusCode,
				"responseStatus":  response.Status,
				"responseBody":    base64.StdEncoding.EncodeToString(resBody),
			})

			if err != nil {
				log.Println("Error marshaling json for webconsole:", err)
			}

			if response.Request != nil {
				hostLocation, err := base64.StdEncoding.DecodeString(response.Request.URL.Host)
				if err != nil {
					log.Println("Error loading proxy info from request", err)
				}

				c.Set("proxySocket", string(hostLocation))
			}

			state.Console.BroadcastRoute(hostname, data)
		}

		return nil
	}
}
