package main

import (
	"context"
	"fmt"
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

	t.Run("Successful proxy", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12080")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
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
