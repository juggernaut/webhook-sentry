/**
* Copyright (c) 2020 Ameya Lokare
 */
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/juggernaut/webhook-sentry/certutil"
	"github.com/juggernaut/webhook-sentry/proxy"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	proxyHttpAddress                         = "127.0.0.1:11090"
	proxyHttpsAddress                        = "127.0.0.1:11091"
	httpTargetServerPort                     = "12080"
	httpsTargetServerPort                    = "12081"
	httpsTargetServerWithClientCertCheckPort = "12089"
)

type testFixture struct {
	certificates   *certutil.CertificateFixtures
	configSetup    func(*proxy.ProxyConfig, *certutil.CertificateFixtures)
	serversSetup   func(*certutil.CertificateFixtures) []*http.Server
	transportSetup func(*http.Transport, *certutil.CertificateFixtures)
	proxy          *http.Server
	proxyType      proxy.Protocol
	servers        []*http.Server
}

func (f *testFixture) setUp(t *testing.T) *http.Client {
	if f.certificates == nil {
		f.certificates = certutil.NewCertificateFixtures(t)
	}
	proxyConfig := proxy.NewDefaultConfig()
	if f.configSetup != nil {
		f.configSetup(proxyConfig, f.certificates)
	}
	if f.proxyType == "" {
		f.proxyType = proxy.HTTP
	}
	switch f.proxyType {
	case proxy.HTTP:
		f.proxy = startProxy(t, proxyConfig)
	case proxy.HTTPS:
		f.proxy = startTLSProxyWithCert(t, proxyConfig, f.certificates.ProxyCert)
	}

	if f.serversSetup == nil {
		t.Fatal("Target servers must be setup in test fixture!")
	}

	f.servers = f.serversSetup(f.certificates)
	waitForStartup(t, f.proxy.Addr)

	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			if f.proxyType == proxy.HTTP {
				return url.Parse("http://" + proxyHttpAddress)
			} else {
				return url.Parse("https://" + proxyHttpsAddress)
			}
		},
	}
	if f.transportSetup != nil {
		f.transportSetup(tr, f.certificates)
	}
	return &http.Client{Transport: tr}
}

func (f *testFixture) tearDown(t *testing.T) {
	if f.proxy != nil {
		f.proxy.Shutdown(context.TODO())
	}
	for _, s := range f.servers {
		s.Shutdown(context.TODO())
	}
}

func assertForbiddenIP(client *http.Client, host string, t *testing.T) {
	resp, err := client.Get(fmt.Sprintf("http://%s:%s", host, httpTargetServerPort))
	if err != nil {
		t.Errorf("Error in GET request to target server via proxy: %s\n", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected status code 403, got %d\n", resp.StatusCode)
	}
	errorCode, ok := resp.Header[http.CanonicalHeaderKey(proxy.ReasonCodeHeader)]
	if !ok {
		t.Errorf("Error code header not present")
	}
	errorCodeI, err := strconv.Atoi(errorCode[0])
	if err != nil {
		t.Fatal(err)
	}
	if uint16(errorCodeI) != proxy.BlockedIPAddress {
		t.Errorf("Expected errorCode %d, but found %s", proxy.BlockedIPAddress, errorCode[0])
	}
}

func TestPrivateNetworkForbidden(t *testing.T) {
	fixture := &testFixture{
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			server := startTargetServer(t, nil)
			return []*http.Server{server}
		},
	}

	client := fixture.setUp(t)

	t.Run("Localhost forbidden", func(t *testing.T) {
		assertForbiddenIP(client, "localhost", t)
	})

	t.Run("RFC 1918 addresses forbidden", func(t *testing.T) {
		assertForbiddenIP(client, "10.1.1.1", t)
		assertForbiddenIP(client, "172.16.1.1", t)
	})

	fixture.tearDown(t)
}

func TestProxy(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
		},
		serversSetup: func(certificates *certutil.CertificateFixtures) []*http.Server {
			var servers []*http.Server
			httpServer := startTargetServer(t, nil)
			httpsServer := startTargetHTTPSServerWithInMemoryCert(t, certificates.InvalidHostnameServerCert)
			return append(servers, httpServer, httpsServer)
		},
	}

	client := fixture.setUp(t)

	t.Run("Proxy 200 OK", func(t *testing.T) {
		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/target", httpTargetServerPort))
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
		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/someRandomPath", httpTargetServerPort))
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 404 {
			t.Errorf("Expected status code 404, got %d\n", resp.StatusCode)
		}
	})

	t.Run("HTTPS target using header fails due to invalid hostname in cert", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s", httpsTargetServerPort), nil)
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

	fixture.tearDown(t)
}

func TestHTTPSTargets(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, certificates *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.InsecureSkipCertVerification = true
			config.ClientCerts = make(map[string]tls.Certificate)
			config.ClientCerts["default"] = *certificates.ClientCert
		},
		serversSetup: func(certificates *certutil.CertificateFixtures) []*http.Server {
			var servers []*http.Server
			httpsServer := startTargetHTTPSServerWithInMemoryCert(t, certificates.ServerCert)
			httpsServerWithClientCertCheck := startTargetHTTPSServerWithClientCertCheck(t, certificates.ServerCert, certificates.RootCAs)
			return append(servers, httpsServer, httpsServerWithClientCertCheck)
		},
	}

	client := fixture.setUp(t)

	t.Run("Successful proxy to HTTPS target", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpsTargetServerPort), nil)
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

	t.Run("Unknown client cert", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpsTargetServerWithClientCertCheckPort), nil)
		if err != nil {
			t.Fatalf("Failed to create new request: %s\n", err)
		}
		req.Header.Add("X-WHSentry-TLS", "true")
		req.Header.Add("X-WHSentry-ClientCert", "foobar")
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 400 {
			t.Errorf("Expected status code 400, got %d\n", resp.StatusCode)
		}
		errorCode, ok := resp.Header[http.CanonicalHeaderKey(proxy.ReasonCodeHeader)]
		if !ok {
			t.Errorf("Error Code header not present")
		}
		errorCodeI, err := strconv.Atoi(errorCode[0])
		if err != nil {
			t.Fatal(err)
		}
		if uint16(errorCodeI) != proxy.ClientCertNotFoundError {
			t.Errorf("Expected %d errorCode, got %s", proxy.ClientCertNotFoundError, errorCode[0])
		}
	})

	t.Run("Successful proxy to HTTPS target that checks client cert using implicit default client cert", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpsTargetServerWithClientCertCheckPort), nil)
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
		if buf.String() != "Hello from target HTTPS with client cert check" {
			t.Errorf("Expected string 'Hello from target HTTPS with client cert check' in response, but was %s\n", buf.String())
		}
	})

	t.Run("Successful proxy to HTTPS target that checks client cert with explicit cert specified", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpsTargetServerWithClientCertCheckPort), nil)
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

	fixture.tearDown(t)

}

func TestHttpConnectNotAllowedByDefault(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.InsecureSkipCertVerification = true
		},
		serversSetup: func(certificates *certutil.CertificateFixtures) []*http.Server {
			target := startTargetHTTPSServerWithInMemoryCert(t, certificates.ServerCert)
			return []*http.Server{target}
		},
	}
	client := fixture.setUp(t)
	_, err := client.Get(fmt.Sprintf("https://localhost:%s/target", httpsTargetServerPort))
	if err == nil {
		t.Error("Expected to get error because CONNECT is disallowed, instead got no error")
	}
	if !strings.Contains(err.Error(), "Method Not Allowed") {
		t.Errorf("Expected error '%s' to contain string 'Method Not Allowed'", err.Error())
	}
	fixture.tearDown(t)
}

func TestMitmHttpConnect(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			// This only disables the cert verification for the target server from the proxy, not from client to (MITM) proxy
			config.InsecureSkipCertVerification = true
			config.MitmIssuerCert = c.RootCACert
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			server := startTargetHTTPSServerWithInMemoryCert(t, c.ServerCert)
			return []*http.Server{server}
		},
		transportSetup: func(tr *http.Transport, c *certutil.CertificateFixtures) {
			tr.TLSClientConfig = &tls.Config{
				RootCAs: c.RootCAs,
			}
		},
	}

	client := fixture.setUp(t)

	resp, err := client.Get(fmt.Sprintf("https://localhost:%s/target", httpsTargetServerPort))
	if err != nil {
		t.Fatalf("Got error requesting CONNECT to HTTPS target: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got status code %d", resp.StatusCode)
	}

	fixture.tearDown(t)
}

func TestOutboundConnectionLifetime(t *testing.T) {

	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.ConnectionLifetime = time.Second * 5
			config.ReadTimeout = time.Second * 2
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			// These are not http.Server unfortunately
			go startSlowToRespondServer(t)
			go startNeverSendsBodyServer(t)
			return []*http.Server{}
		},
	}

	client := fixture.setUp(t)

	t.Run("test connection lifetime", func(t *testing.T) {
		resp, err := client.Get("http://localhost:14400/")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 502 {
			t.Errorf("Expected status code 502, got %d\n", resp.StatusCode)
		}
		errorCode, ok := resp.Header[http.CanonicalHeaderKey(proxy.ReasonCodeHeader)]
		if !ok {
			t.Errorf("Error Code header not present")
		}
		errorCodeI, err := strconv.Atoi(errorCode[0])
		if err != nil {
			t.Fatal(err)
		}
		if uint16(errorCodeI) != proxy.RequestTimedOut {
			t.Errorf("Expected %d errorCode, got %s", proxy.RequestTimedOut, errorCode[0])
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

	fixture.tearDown(t)

}

func TestProxyTrustsTargetSignedWithCustomRootCA(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			// This is false by default, but make it explicit for clarity
			config.InsecureSkipCertVerification = false
			config.RootCACerts = c.RootCAs
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			server := startTargetHTTPSServerWithInMemoryCert(t, c.ServerCert)
			return []*http.Server{server}
		},
	}

	client := fixture.setUp(t)

	t.Run("Successful proxy to HTTPS target with custom root CA", func(t *testing.T) {
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

	fixture.tearDown(t)

}

func TestHTTPSProxyListener(t *testing.T) {
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.InsecureSkipCertVerification = false
			config.RootCACerts = c.RootCAs
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			httpServer := startTargetServer(t, nil)
			httpsServer := startTargetHTTPSServerWithInMemoryCert(t, c.ServerCert)
			return []*http.Server{httpServer, httpsServer}
		},
		proxyType: proxy.HTTPS,
		transportSetup: func(tr *http.Transport, c *certutil.CertificateFixtures) {
			tr.TLSClientConfig = &tls.Config{
				RootCAs: c.RootCAs,
			}
		},
	}

	client := fixture.setUp(t)

	t.Run("Test HTTPS proxy -> HTTP target", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpTargetServerPort), nil)
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
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/target", httpsTargetServerPort), nil)
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

	fixture.tearDown(t)
}

func TestContentLengthLimit(t *testing.T) {
	maxContentLength := 8
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.MaxResponseBodySize = uint32(maxContentLength)
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			server := startLargeContentLengthServer(t)
			return []*http.Server{server}
		},
	}

	client := fixture.setUp(t)

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

	fixture.tearDown(t)
}

func TestChunkedResponseContentLengthLimit(t *testing.T) {
	maxContentLength := 8 * 1024
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
			config.MaxResponseBodySize = uint32(maxContentLength)
		},
		serversSetup: func(c *certutil.CertificateFixtures) []*http.Server {
			server := startLargeContentLengthServer(t)
			return []*http.Server{server}
		},
	}

	client := fixture.setUp(t)

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

	// NOTE: this isn't a great test because if the proxy cuts off the response at a chunk
	// boundary, the client can parse it correctly, otherwise the parsing fails. In this particular
	// instance, it looks like the response is being cut off at a chunk boundary.
	t.Run("Over max content length", func(t *testing.T) {
		resp, err := client.Get("http://localhost:12099/oversize")
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Got error %s\n", err)
		}
		if len(responseData) != maxContentLength {
			t.Fatalf("Expected response length %d, got %d", maxContentLength, len(responseData))
		}
	})
	fixture.tearDown(t)
}

func TestRequestContentLength(t *testing.T) {
	headerChan := make(chan map[string][]string, 1)
	fixture := &testFixture{
		configSetup: func(config *proxy.ProxyConfig, c *certutil.CertificateFixtures) {
			config.InsecureSkipCidrDenyList = true
		},
		serversSetup: func(certificates *certutil.CertificateFixtures) []*http.Server {
			var servers []*http.Server
			httpServer := startTargetServer(t, headerChan)
			return append(servers, httpServer)
		},
	}

	client := fixture.setUp(t)

	t.Run("Request with content length header is passed along to target", func(t *testing.T) {
		resp, err := client.Post(fmt.Sprintf("http://localhost:%s/target", httpTargetServerPort), "text/plain", strings.NewReader("Hello webhook sentry!"))
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
		headers := <-headerChan
		cl, ok := headers["Content-Length"]
		if !ok {
			t.Error("No Content-Length found in request headers")
		}

		expectedLen := len("Hello webhook sentry!")
		if cl[0] != strconv.Itoa(expectedLen) {
			t.Errorf("Expected Content-Length %d, but found %s", expectedLen, cl[0])
		}
	})

	t.Run("Request with Transfer-Encoding chunked is passed along to target", func(t *testing.T) {
		req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%s/target", httpTargetServerPort), strings.NewReader("Hello webhook sentry!"))
		if err != nil {
			t.Fatal(err)
		}
		req.TransferEncoding = []string{"chunked"}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("Error in GET request to target server via proxy: %s\n", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d\n", resp.StatusCode)
		}
		headers := <-headerChan
		_, ok := headers["Content-Length"]
		if ok {
			t.Error("Expected absence of Content-Length in request headers, but was found")
		}

		te, ok := headers["Transfer-Encoding"]
		if !ok {
			t.Error("Expected Transfer-Encoding in request headers, but was not found")
		}
		if te[0] != "chunked" {
			t.Errorf("Expected Transfer-Encoding value 'chunked', but was %s", te[0])
		}
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
			conn.Close()
			break
		}
	}
}

func startProxy(t *testing.T, p *proxy.ProxyConfig) *http.Server {
	proxy.SetupLogging(p)
	p.Listeners = make([]proxy.ListenerConfig, 1, 1)
	p.Listeners[0] = proxy.ListenerConfig{
		Address: proxyHttpAddress,
		Type:    proxy.HTTP,
	}
	proxy := proxy.CreateProxyServers(p)[0]
	go func() {
		listener, err := net.Listen("tcp4", p.Listeners[0].Address)
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		proxy.Serve(listener)
	}()
	return proxy
}

func startTLSProxy(t *testing.T, p *proxy.ProxyConfig) *http.Server {
	proxy.SetupLogging(p)
	p.Listeners = make([]proxy.ListenerConfig, 1, 1)
	p.Listeners[0] = proxy.ListenerConfig{
		Address:  proxyHttpsAddress,
		Type:     proxy.HTTP,
		CertFile: "certs/cert.pem",
		KeyFile:  "certs/key.pem",
	}
	pServer := proxy.CreateProxyServers(p)[0]
	go func() {
		listener, err := net.Listen("tcp4", p.Listeners[0].Address)
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		pServer.ServeTLS(listener, p.Listeners[0].CertFile, p.Listeners[0].KeyFile)
	}()
	return pServer
}

func startTLSProxyWithCert(t *testing.T, p *proxy.ProxyConfig, proxyCert *tls.Certificate) *http.Server {
	proxy.SetupLogging(p)
	p.Listeners = make([]proxy.ListenerConfig, 1, 1)
	p.Listeners[0] = proxy.ListenerConfig{
		Address: proxyHttpsAddress,
		Type:    proxy.HTTP,
	}
	pServer := proxy.CreateProxyServers(p)[0]
	go func() {
		config := &tls.Config{Certificates: []tls.Certificate{*proxyCert}}
		listener, err := tls.Listen("tcp4", p.Listeners[0].Address, config)
		if err != nil {
			t.Fatalf("Could not start proxy listener: %s\n", err)
		}
		pServer.Serve(listener)
	}()
	return pServer
}

func startTargetServer(t *testing.T, headerChan chan map[string][]string) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		if headerChan != nil {
			headers := r.Header.Clone()
			// Hack to add Transfer-Encoding, since the headers map doesn't seem to have it
			if r.TransferEncoding != nil {
				headers["Transfer-Encoding"] = r.TransferEncoding
			}
			headerChan <- headers
		}
		w.Header().Set("X-Custom-Header", "custom")
		fmt.Fprint(w, "Hello from target")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:" + httpTargetServerPort,
		Handler: serveMux,
	}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			t.Fatalf("Failed to start target HTTP server: %s\n", err)
		}
	}()
	return server
}

func startTargetHTTPSServer(t *testing.T) *http.Server {
	return startTargetHTTPSServerWithCert(t, "certs/cert.pem", "certs/key.pem")
}

func startTargetHTTPSServerWithCert(t *testing.T, certFile string, keyFile string) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target HTTPS")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:12081",
		Handler: serveMux,
	}
	go func() {
		if err := server.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
			t.Fatalf("HTTPS server failed to start: %s\n", err)
		}
	}()
	return server
}

func startTargetHTTPSServerWithInMemoryCert(t *testing.T, serverCert *tls.Certificate) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target HTTPS")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:" + httpsTargetServerPort,
		Handler: serveMux,
	}
	go func() {
		config := &tls.Config{Certificates: []tls.Certificate{*serverCert}}
		listener, err := tls.Listen("tcp4", server.Addr, config)
		if err != nil {
			t.Fatalf("Failed to listen on port %s: %s\n", httpsTargetServerPort, err)
		}
		if err := server.Serve(listener); err != http.ErrServerClosed {
			t.Fatalf("HTTPS target server failed to start: %s\n", err)
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

func startTargetHTTPSServerWithClientCertCheck(t *testing.T, serverCert *tls.Certificate, rootCAs *x509.CertPool) *http.Server {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from target HTTPS with client cert check")
	})

	server := &http.Server{
		Addr:    "127.0.0.1:" + httpsTargetServerWithClientCertCheckPort,
		Handler: serveMux,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}

	go func() {
		listener, err := tls.Listen("tcp4", "127.0.0.1:"+httpsTargetServerWithClientCertCheckPort, tlsConfig)
		if err != nil {
			t.Fatalf("Failed to listen on port %s: %s\n", httpsTargetServerWithClientCertCheckPort, err)
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
