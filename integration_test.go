package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestLocalNetworkForbidden(t *testing.T) {
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startTargetServer(t)
	defer targetServer.Shutdown(context.TODO())

	waitForStartup(t)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("Localhost forbidden", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12080")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 403 {
			t.Errorf("Expected status code 403, got %d\n", resp.StatusCode)
		}
	})

}

func TestProxy(t *testing.T) {
	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startTargetServer(t)
	defer targetServer.Shutdown(context.TODO())

	waitForStartup(t)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("Proxy 200 OK", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12080/target")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
	})

	t.Run("Proxy 404 Not Found", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12080/someRandomPath")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 404 {
			t.Errorf("Expected status code 404, got %d\n", resp.StatusCode)
		}
	})

	httpsServer := startTargetHTTPSServer(t)
	defer httpsServer.Shutdown(context.TODO())

	t.Run("HTTPS target using header fails due to invalid hostname in cert", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:12081", nil)
		if err != nil {
			t.Fatalf("Failed to create new request: %s\n", err)
		}
		req.Header.Add("X-WHSentry-TLS", "true")
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 502 {
			t.Errorf("Expected status code 502, got %d\n", resp.StatusCode)
		}
	})
}

func TestHTTPS(t *testing.T) {
	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	os.Setenv("UNSAFE_SKIP_CERT_VERIFICATION", "true")
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	httpsServer := startTargetHTTPSServer(t)
	defer httpsServer.Shutdown(context.TODO())

	waitForStartup(t)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("Successful HTTPS proxy", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:12081/target", nil)
		if err != nil {
			t.Fatalf("Failed to create new request: %s\n", err)
		}
		req.Header.Add("X-WHSentry-TLS", "true")
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
	})

	t.Run("Successful CONNECT proxy", func(t *testing.T) {
		// Notice we don't add any header here, and target URL is https, however we
		// need to disable cert validation on the client (not proxy) since proxy is now
		// transparent
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		resp, err := client.Get("https://localhost:12081/target")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
	})

}

func TestOutboundConnectionLifetime(t *testing.T) {

	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	os.Setenv("CONNECTION_LIFETIME", "5s")
	os.Setenv("IDLE_READ_TIMEOUT", "2s")
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())
	go startSlowToRespondServer(t)
	go startNeverSendsBodyServer(t)

	waitForStartup(t)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("test connection lifetime", func(t *testing.T) {
		resp, err := client.Get("http://localhost:14400/")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 502 {
			t.Errorf("Expected status code 502, got %d\n", resp.StatusCode)
		}
	})

	t.Run("test socket read timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost:14402/", nil)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		buf := make([]byte, resp.ContentLength, resp.ContentLength)
		_, err = resp.Body.Read(buf)
		if err != io.ErrUnexpectedEOF {
			t.Errorf("Expected a 'UnexpectedEOF' error, instead got: %s\n", err)
		}
		duration := time.Now().Sub(start)
		if !(duration.Seconds() >= 1.9 && duration.Seconds() <= 2.2) {
			t.Errorf("Expected read timeout (and hence connection close) at ~2 seconds, instead it took %f seconds", duration.Seconds())
		}

	})

}

func waitForStartup(t *testing.T) {
	i := 0
	for {
		conn, err := net.Dial("tcp4", "127.0.0.1:11090")
		if err != nil {
			if i > 2 {
				t.Error("Proxy did not start up in time")
				break
			} else {
				time.Sleep(500 * time.Millisecond)
				i++
			}
		} else {
			t.Log("Proxy started, now running tests")
			conn.Close()
			break
		}
	}
}

func startProxy(t *testing.T) *http.Server {
	proxy := BuildProxyServer("127.0.0.1:11090")
	go func() {
		listener, err := net.Listen("tcp4", "127.0.0.1:11090")
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		proxy.Serve(listener)
	}()
	return proxy
}

func startTargetServer(t *testing.T) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:12080",
		Handler: serveMux,
	}
	go func() {
		server.ListenAndServe()
	}()
	return server
}

func startTargetHTTPSServer(t *testing.T) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target HTTPS")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:12081",
		Handler: serveMux,
	}
	go func() {
		if err := server.ListenAndServeTLS("certs/cert.pem", "certs/key.pem"); err != http.ErrServerClosed {
			t.Fatalf("HTTPS server failed to start: %s\n", err)
		}
	}()
	return server

}

func startSlowToRespondServer(t *testing.T) {
	listener, err := net.Listen("tcp4", ":14400")
	if err != nil {
		t.Fatalf("Failed to start slow server: %s\n", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection in slow server: %s\n", err)
	}
	defer conn.Close()
	time.Sleep(time.Second * 7)
	bufw := bufio.NewWriter(conn)
	bufw.WriteString("HTTP/1.1 200 OK\r\n")
	bufw.WriteString("Connection: Close\r\n")
	bufw.WriteString("\r\n")
	bufw.Flush()
}

func startNeverSendsBodyServer(t *testing.T) {
	listener, err := net.Listen("tcp4", ":14402")
	if err != nil {
		t.Fatalf("Failed to start never sends body server: %s\n", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection in never sends body server: %s\n", err)
	}
	defer conn.Close()
	bufw := bufio.NewWriter(conn)
	bufw.WriteString("HTTP/1.1 200 OK\r\n")
	bufw.WriteString("Connection: Close\r\n")
	bufw.WriteString("Content-Length: 5\r\n")
	bufw.WriteString("\r\n")
	bufw.Flush()

	time.Sleep(time.Second * 5)
	bufw.WriteString("hello")
	bufw.Flush()
}
