package gateway

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResponseInspectionAndUpstreamTLS(t *testing.T) {
	a, _, _ := testApp(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/large":
			io.WriteString(w, strings.Repeat("x", (1<<20)+1))
		case "/leak":
			io.WriteString(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
		default:
			io.WriteString(w, "<p>Safe response</p>")
		}
	}))
	defer backend.Close()
	change(t, a, func(c *Config) { c.ResponseInspection = true; c.Routes[0].Upstreams = []string{backend.URL} })
	for _, tc := range []struct {
		path   string
		status int
	}{{"/", 200}, {"/large", 502}, {"/leak", 403}} {
		w := request(a, "GET", tc.path, "", "")
		if w.Code != tc.status {
			t.Fatalf("%s: got %d want %d (%+v)", tc.path, w.Code, tc.status, a.Events.list()[0])
		}
		if tc.path == "/leak" && strings.Contains(w.Body.String(), "SQL syntax") {
			t.Fatal("sensitive response leaked")
		}
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS upstream reached") }))
	defer secure.Close()
	change(t, a, func(c *Config) { c.Routes[0].Upstreams = []string{secure.URL} })
	if w := request(a, "GET", "/", "", ""); w.Code != 502 {
		t.Fatalf("untrusted certificate accepted: %d", w.Code)
	}
}
func TestWebSocketUpgrade(t *testing.T) {
	a, _, _ := testApp(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		buf.Flush()
		frame := make([]byte, 8)
		if _, err := io.ReadFull(buf, frame); err == nil {
			conn.Write([]byte{0x81, 2, 'o', 'k'})
		}
	}))
	defer backend.Close()
	change(t, a, func(c *Config) { c.Routes[0].Upstreams = []string{backend.URL} })
	proxy := httptest.NewServer(a)
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upgrade: %d %s", resp.StatusCode, b)
	}
	conn.Write([]byte{0x81, 0x82, 0, 0, 0, 0, 'h', 'i'})
	frame := make([]byte, 4)
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal(err)
	}
	if string(frame[2:]) != "ok" {
		t.Fatal("websocket not tunneled")
	}
	conn.Close()
	deadline := time.Now().Add(time.Second)
	for len(a.Events.list()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}
func TestMalformedAndCompressedRequests(t *testing.T) {
	a, _, hits := testApp(t)
	before := hits.Load()
	if w := request(a, "POST", "/", `{"broken":`, "application/json"); w.Code < 400 {
		t.Fatalf("malformed JSON passed: %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader("compressed bytes"))
	r.Host = "app.example.com"
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
	if hits.Load() != before {
		t.Fatal("unsupported body reached upstream")
	}
	r = httptest.NewRequest("GET", "http://app.example.com/", nil)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("absolute request accepted")
	}
}
func TestRuleExclusionsAndConcurrentReload(t *testing.T) {
	a, _, _ := testApp(t)
	change(t, a, func(c *Config) { c.Routes[0].ExcludedRuleIDs = []int{920350}; c.RateLimit = 10000 })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if w := request(a, "GET", "/", "", ""); w.Code != 200 {
					t.Errorf("request during reload: %d", w.Code)
				}
			}
		}()
	}
	change(t, a, func(c *Config) { c.Paranoia = 2 })
	wg.Wait()
}
