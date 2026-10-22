package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/antoniomika/sish/utils"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/viper"
)

// gzipBytes returns the gzip encoding of data, as an upstream would send it.
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		t.Fatalf("unable to gzip test data: %s", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("unable to close gzip writer: %s", err)
	}

	return buf.Bytes()
}

// runResponseModifier feeds a response carrying the given body and
// Content-Encoding through ResponseModifier and returns the body it recorded
// for the console alongside the body left for the client.
func runResponseModifier(t *testing.T, contentEncoding string, body []byte) (consoleBody []byte, clientBody []byte) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("admin-console", true)
	viper.Set("service-console-max-content-length", int64(-1))

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)

	listener := &utils.HTTPHolder{HTTPUrl: &url.URL{Scheme: "http", Host: "test.example.com"}}

	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	if contentEncoding != "" {
		response.Header.Set("Content-Encoding", contentEncoding)
	}

	if err := ResponseModifier(nil, "test.example.com", nil, c, listener)(response); err != nil {
		t.Fatalf("ResponseModifier returned an error: %s", err)
	}

	data, ok := c.Get("broadcastData")
	if !ok {
		t.Fatal("ResponseModifier did not set broadcastData")
	}

	encoded, ok := data.(map[string]any)["responseBody"].(string)
	if !ok {
		t.Fatal("broadcastData did not carry a responseBody string")
	}

	consoleBody, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("unable to decode recorded response body: %s", err)
	}

	clientBody, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("unable to read the response body left for the client: %s", err)
	}

	return consoleBody, clientBody
}

// A 304 carries no body, but static file servers still label it
// Content-Encoding: gzip. Decoding it must not take the proxy down.
func TestResponseModifierEmptyGzipBody(t *testing.T) {
	consoleBody, clientBody := runResponseModifier(t, "gzip", nil)

	if len(consoleBody) != 0 {
		t.Errorf("expected an empty recorded body, got %q", consoleBody)
	}

	if len(clientBody) != 0 {
		t.Errorf("expected an empty body for the client, got %q", clientBody)
	}
}

func TestResponseModifierCorruptGzipBody(t *testing.T) {
	body := []byte("this is not gzip data")

	consoleBody, clientBody := runResponseModifier(t, "gzip", body)

	if !bytes.Equal(consoleBody, body) {
		t.Errorf("expected the undecodable body to be recorded as-is, got %q", consoleBody)
	}

	if !bytes.Equal(clientBody, body) {
		t.Errorf("expected the body for the client to be untouched, got %q", clientBody)
	}
}

func TestResponseModifierValidGzipBody(t *testing.T) {
	plain := []byte("hello sish")
	compressed := gzipBytes(t, plain)

	consoleBody, clientBody := runResponseModifier(t, "gzip", compressed)

	if !bytes.Equal(consoleBody, plain) {
		t.Errorf("expected the decoded body to be recorded, got %q", consoleBody)
	}

	if !bytes.Equal(clientBody, compressed) {
		t.Errorf("expected the body for the client to stay compressed, got %q", clientBody)
	}
}

func TestResponseModifierPlainBody(t *testing.T) {
	body := []byte("hello sish")

	consoleBody, clientBody := runResponseModifier(t, "", body)

	if !bytes.Equal(consoleBody, body) {
		t.Errorf("expected the plain body to be recorded, got %q", consoleBody)
	}

	if !bytes.Equal(clientBody, body) {
		t.Errorf("expected the body for the client to be untouched, got %q", clientBody)
	}
}

func TestResponseModifierOtherEncodings(t *testing.T) {
	plain := []byte("hello sish")

	var br, zl bytes.Buffer

	bw := brotli.NewWriter(&br)
	_, _ = bw.Write(plain)
	_ = bw.Close()

	zw := zlib.NewWriter(&zl)
	_, _ = zw.Write(plain)
	_ = zw.Close()

	zenc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("unable to create zstd writer: %s", err)
	}

	bodies := map[string][]byte{
		"br":      br.Bytes(),
		"deflate": zl.Bytes(),
		"zstd":    zenc.EncodeAll(plain, nil),
	}

	for encoding, compressed := range bodies {
		t.Run(encoding, func(t *testing.T) {
			consoleBody, clientBody := runResponseModifier(t, encoding, compressed)

			if !bytes.Equal(consoleBody, plain) {
				t.Errorf("expected the decoded body to be recorded, got %q", consoleBody)
			}

			if !bytes.Equal(clientBody, compressed) {
				t.Errorf("expected the body for the client to stay compressed, got %q", clientBody)
			}
		})
	}
}

// A small compressed body can decode to far more than the limit.
func TestDecodeConsoleBodyLimit(t *testing.T) {
	compressed := gzipBytes(t, bytes.Repeat([]byte("a"), 4096))

	if got := decodeConsoleBody(compressed, "gzip", 1024); !bytes.Equal(got, notCapturedResponse) {
		t.Errorf("expected the not captured body, got %d bytes", len(got))
	}
}
