package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	go main()
	go startTargetServer()
	waitForStartup(t)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:9090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("simple proxied", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12080")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 403 {
			t.Errorf("Expected status code 403, got %d\n", resp.StatusCode)
		}
	})
}

func waitForStartup(t *testing.T) {
	i := 0
	for {
		conn, err := net.Dial("tcp4", "127.0.0.1:9090")
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

func startTargetServer() {
	http.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target")
	})
	http.ListenAndServe("127.0.0.1:12080", nil)
}
