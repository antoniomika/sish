package httpmuxer

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/sish/wsinspect"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// inspectWebSocket shows an upgraded WebSocket connection in the console as soon as it opens,
// then reports each message and the close as they pass through the tunnel.
func inspectWebSocket(state *utils.State, hostname string, reqBody []byte, c *gin.Context, currentListener *utils.HTTPHolder, response *http.Response) {
	backend, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		return
	}

	route := currentListener.HTTPUrl.String()
	opened := time.Now()

	data := requestData(c, hostname, reqBody)
	data["websocket"] = true
	data["responseHeaders"] = response.Header
	data["responseBody"] = ""
	data["responseCode"] = response.StatusCode
	data["responseStatus"] = fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode))
	data["requestTime"] = opened.Sub(c.GetTime("startTime")).Round(10 * time.Microsecond).String()

	id := state.Console.BroadcastRoute(route, data)
	if id == 0 {
		return
	}

	var seq atomic.Uint64
	event := func(kind string, fields map[string]any) {
		fields["type"] = kind
		fields["seq"] = seq.Add(1)
		fields["time"] = time.Now()
		state.Console.BroadcastEvent(route, id, fields)
	}

	response.Body = wsinspect.NewConn(backend, response.Header, viper.GetInt("service-console-max-content-length"), wsinspect.Handler{
		Message: func(dir wsinspect.Direction, m wsinspect.Message) {
			fields := map[string]any{
				"direction":  dir,
				"opcode":     wsinspect.OpcodeName(m.Opcode),
				"size":       m.Size,
				"payload":    base64.StdEncoding.EncodeToString(m.Payload),
				"truncated":  m.Truncated,
				"compressed": m.Compressed,
				"undecoded":  m.Undecoded,
			}

			if m.Opcode == wsinspect.OpClose {
				fields["closeCode"] = m.CloseCode
				fields["closeReason"] = m.CloseReason
			}

			event("ws-message", fields)
		},
		Error: func(dir wsinspect.Direction, err error) {
			event("ws-error", map[string]any{"direction": dir, "error": err.Error()})
		},
		Close: func() {
			event("ws-close", map[string]any{"duration": time.Since(opened).Round(time.Millisecond).String()})
		},
	})
}
