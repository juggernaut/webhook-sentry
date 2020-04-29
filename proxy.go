package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var skipHeaders = [...]string{"Connection", "Proxy-Connection", "User-Agent"}

func main() {
	fmt.Printf("Hello egress proxy\n")
	dialer := &net.Dialer{
		Timeout:   time.Duration(30) * time.Second,
		DualStack: false,
		KeepAlive: -1,
	}
	tr := &http.Transport{
		Proxy:             nil,
		IdleConnTimeout:   time.Duration(20) * time.Second,
		DisableKeepAlives: true,
		DialContext:       (&safeDialer{dialer: dialer}).DialContext,
	}
	server := &http.Server{
		Addr:           ":9090",
		Handler:        ProxyHTTPHandler{roundTripper: tr},
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

// some struct
type ProxyHTTPHandler struct {
	roundTripper http.RoundTripper
}

func (m ProxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Host is %s\n", r.Host)
	log.Printf("URL is %s\n", r.URL.String())
	if !r.URL.IsAbs() {
		http.Error(w, "Request URI must be absolute", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "Scheme must be HTTP", http.StatusBadRequest)
		return
	}
	//fmt.Fprintf(w, "Hello Go HTTP")
	var outboundUri = r.RequestURI
	if isTLS(r.Header) {
		outboundUri = strings.Replace(outboundUri, "http", "https", 1)
	}
	outboundRequest, err := http.NewRequest(r.Method, outboundUri, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	copyHeaders(r.Header, outboundRequest.Header)
	outboundRequest.Header["User-Agent"] = []string{"Webhook Sentry/0.1"}
	resp, err := m.roundTripper.RoundTrip(outboundRequest)
	if err != nil {
		log.Fatal(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	resp.Write(w)
}

func isTLS(h http.Header) bool {
	tlsHeader, ok := h["X-Whsentry-Tls"]
	if ok {
		for _, val := range tlsHeader {
			if val == "0" || strings.EqualFold(val, "false") {
				return false
			}
		}
		return true
	}
	return false
}

func copyHeaders(inHeader http.Header, outHeader http.Header) {
	for name, values := range inHeader {
		var skipHeader = false
		for _, skipHeaderName := range skipHeaders {
			if name == skipHeaderName {
				skipHeader = true
				break
			}
		}
		if strings.HasPrefix(name, "X-Whsentry") {
			skipHeader = true
		}
		if !skipHeader {
			for _, value := range values {
				outHeader.Add(name, value)
			}
		}
	}
}

type safeDialer struct {
	dialer *net.Dialer
}

func (s *safeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("safeDialZContext Called with addr %s\n", addr)
	//resolvedAddr, err := net.ResolveTCPAddr("tcp4", addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := s.dialer.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var chosenAddr string
	for _, ip := range ips {
		if strings.Count(ip.IP.String(), ":") < 2 {
			chosenAddr = ip.IP.String()
			break
		}
	}
	if chosenAddr == "" {
		return nil, fmt.Errorf("Target %s did not resolve to a valid IPv4 address", addr)
	}
	ipPort := net.JoinHostPort(chosenAddr, port)
	log.Printf("Chosen address is %s\n", ipPort)
	return s.dialer.DialContext(ctx, "tcp4", ipPort)
}
