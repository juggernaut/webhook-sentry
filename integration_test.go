package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const proxyHttpAddress = "127.0.0.1:11090"
const proxyHttpsAddress = "127.0.0.1:11091"

func TestLocalNetworkForbidden(t *testing.T) {
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startTargetServer(t)
	defer targetServer.Shutdown(context.TODO())

	waitForStartup(t, proxyHttpAddress)

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

	waitForStartup(t, proxyHttpAddress)

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
		customHeader := resp.Header.Get("X-Custom-Header")
		if customHeader != "custom" {
			t.Fatalf("Expected custom header to be present, but it is not")
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
	os.Setenv("CLIENT_CERTFILE", "certs/clientcert.pem")
	os.Setenv("CLIENT_KEYFILE", "certs/clientkey.pem")
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	httpsServer := startTargetHTTPSServer(t)
	defer httpsServer.Shutdown(context.TODO())

	httpsWithClientCertCheck := startTargetHTTPSServerWithClientCertCheck(t)
	defer httpsWithClientCertCheck.Shutdown(context.TODO())

	waitForStartup(t, proxyHttpAddress)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("Successful proxy to HTTPS target", func(t *testing.T) {
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
		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp.Body)
		if err != nil {
			t.Errorf("Error while reading body: %s\n", err)
		}
		if buf.String() != "Hello from target HTTPS" {
			t.Errorf("Expected string 'Hello from target HTTPS' in response, but was %s\n", buf.String())
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

	t.Run("Successful proxy to HTTPS target that checks client cert", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:12089/target", nil)
		if err != nil {
			t.Fatalf("Failed to create new request: %s\n", err)
		}
		req.Header.Add("X-WHSentry-TLS", "true")
		req.Header.Add("X-WHSentry-ClientCert", "default")
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp.Body)
		if err != nil {
			t.Errorf("Error while reading body: %s\n", err)
		}
		if buf.String() != "Hello from target HTTPS with client cert check" {
			t.Errorf("Expected string 'Hello from target HTTPS with client cert check' in response, but was %s\n", buf.String())
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

	waitForStartup(t, proxyHttpAddress)

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

func TestHTTPSListener(t *testing.T) {
	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	os.Setenv("UNSAFE_SKIP_CERT_VERIFICATION", "true")
	proxy := startTLSProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startTargetServer(t)
	defer targetServer.Shutdown(context.TODO())

	targetHTTPSServer := startTargetHTTPSServer(t)
	defer targetHTTPSServer.Shutdown(context.TODO())

	waitForStartup(t, proxyHttpsAddress)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			// Notice https in the proxy address
			return url.Parse("https://127.0.0.1:11091")
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	t.Run("Test HTTPS proxy -> HTTP target", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:12080/target", nil)
		if err != nil {
			t.Fatalf("Failed to create new request: %s\n", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
	})

	t.Run("Test HTTPS proxy -> HTTPS target", func(t *testing.T) {
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
		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp.Body)
		if err != nil {
			t.Errorf("Error while reading body: %s\n", err)
		}
		if buf.String() != "Hello from target HTTPS" {
			t.Errorf("Expected string 'Hello from target HTTPS' in response, but was %s\n", buf.String())
		}
	})
}

func TestContentLengthLimit(t *testing.T) {
	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	maxContentLength := 8
	os.Setenv("MAX_RESPONSE_BODY_LENGTH", strconv.Itoa(maxContentLength))
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startLargeContentLengthServer(t)
	defer targetServer.Shutdown(context.TODO())

	waitForStartup(t, proxyHttpAddress)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}

	t.Run("Max content length", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12099/8")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
		if resp.ContentLength != int64(maxContentLength) {
			t.Errorf("Expected Content-length: %d, found %d", maxContentLength, resp.ContentLength)
		}
	})

	t.Run("Over max content length", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12099/9")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 502 {
			t.Errorf("Expected status code 502, got %d\n", resp.StatusCode)
		}
	})
}

func TestChunkedResponseContentLengthLimit(t *testing.T) {
	os.Setenv("UNSAFE_SKIP_CIDR_BLACKLIST", "true")
	maxContentLength := 8 * 1024
	os.Setenv("MAX_RESPONSE_BODY_LENGTH", strconv.Itoa(maxContentLength))
	proxy := startProxy(t)
	defer proxy.Shutdown(context.TODO())

	targetServer := startLargeContentLengthServer(t)
	defer targetServer.Shutdown(context.TODO())

	waitForStartup(t, proxyHttpAddress)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:11090")
		},
	}
	client := &http.Client{Transport: tr}
	//client := &http.Client{}

	t.Run("Max content length", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12099/8k")
		if err != nil {
			t.Fatalf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("Expected status code 200, got %d\n", resp.StatusCode)
		}
		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Error reading response data: %s\n", err)
		}
		if len(responseData) != maxContentLength {
			t.Fatalf("Expected Content-length: %d, found %d", maxContentLength, len(responseData))
		}
	})

	t.Run("Over max content length", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12099/oversize")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Got error %s\n", err)
		}
		t.Logf("Got response data length %d\n", len(responseData))
	})
}

func waitForStartup(t *testing.T, address string) {
	i := 0
	for {
		conn, err := net.Dial("tcp4", address)
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
	setupLogging()
	proxy, _ := BuildProxyServer("127.0.0.1:11090", "")
	go func() {
		listener, err := net.Listen("tcp4", "127.0.0.1:11090")
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		proxy.Serve(listener)
	}()
	return proxy
}

func startTLSProxy(t *testing.T) *http.Server {
	setupLogging()
	_, proxy := BuildProxyServer("", "127.0.0.1:11091")
	go func() {
		listener, err := net.Listen("tcp4", "127.0.0.1:11091")
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		proxy.ServeTLS(listener, "certs/cert.pem", "certs/key.pem")
	}()
	return proxy
}

func startTargetServer(t *testing.T) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom")
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

func startTargetHTTPSServerWithClientCertCheck(t *testing.T) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target HTTPS with client cert check")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:12089",
		Handler: serveMux,
	}
	cert, err := tls.LoadX509KeyPair("certs/cert.pem", "certs/key.pem")
	if err != nil {
		t.Fatalf("Failed to load server certificate key pair %s\n", err)
	}
	clientCACertPool := x509.NewCertPool()
	// This is a little confusing, but the server cert is a self-signed cert that is used to
	// sign the client cert
	caCertBytes, err := ioutil.ReadFile("certs/cert.pem")
	if err != nil {
		t.Fatalf("Failed to read CA cert %s\n", err)
	}
	if !clientCACertPool.AppendCertsFromPEM(caCertBytes) {
		t.Fatal("Failed to append PEM cert to CA cert pool")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCACertPool,
	}

	go func() {
		listener, err := tls.Listen("tcp4", "127.0.0.1:12089", tlsConfig)
		if err != nil {
			t.Fatalf("Failed to listen on port 12089 %s\n", err)
		}

		if err := server.Serve(listener); err != http.ErrServerClosed {
			t.Fatalf("HTTPS server failed to start: %s\n", err)
		}
	}()
	return server

}

func startLargeContentLengthServer(t *testing.T) *http.Server {
	serveMux := http.NewServeMux()
	baseStr := "eight ch"
	content := strings.Repeat(baseStr, 1024)
	serveMux.HandleFunc("/8", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, baseStr)
	})

	serveMux.HandleFunc("/9", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, baseStr+"a")
	})

	serveMux.HandleFunc("/8k", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "oversize")
		fmt.Fprint(w, content)
	})
	serveMux.HandleFunc("/oversize", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, content+"a")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:12099",
		Handler: serveMux,
	}
	go func() {
		server.ListenAndServe()
	}()
	return server
}
