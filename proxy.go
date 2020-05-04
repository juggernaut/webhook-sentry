package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var skipHeaders = [...]string{"Connection", "Proxy-Connection", "User-Agent"}
var cidrBlackListConfig = [...]string{"127.0.0.0/8"}

func main() {
	fmt.Printf("Hello egress proxy\n")
	dialer := &net.Dialer{
		Timeout:   time.Duration(30) * time.Second,
		DualStack: false,
		KeepAlive: -1,
	}

	cidrBlacklist := getCidrBlacklist()

	tr := &http.Transport{
		Proxy:             nil,
		IdleConnTimeout:   time.Duration(20) * time.Second,
		DisableKeepAlives: true,
		DialContext:       (&safeDialer{dialer: dialer, cidrBlacklist: cidrBlacklist}).DialContext,
	}
	server := &http.Server{
		Addr:           ":9090",
		Handler:        ProxyHTTPHandler{roundTripper: tr},
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

func getCidrBlacklist() []net.IPNet {
	if isTruish(os.Getenv("UNSAFE_SKIP_CIDR_BLACKLIST")) {
		return nil
	}

	var cidrBlacklist []net.IPNet
	for _, cidr := range cidrBlackListConfig {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cidrBlacklist = append(cidrBlacklist, *ipNet)
		}
	}
	return cidrBlacklist
}

// some struct
type ProxyHTTPHandler struct {
	roundTripper http.RoundTripper
}

func (m ProxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := m.doProxy(r)
	var responseCode int
	if err != nil {
		responseCode = handleError(w, err)
	} else {
		responseCode = resp.StatusCode
		resp.Write(w)
	}
	logRequest(r, responseCode)
}

func (m ProxyHTTPHandler) doProxy(r *http.Request) (*http.Response, error) {
	if !r.URL.IsAbs() {
		return nil, &proxyError{statusCode: http.StatusBadRequest, message: "Request URI must be absolute"}
	}
	if r.URL.Scheme != "http" {
		return nil, &proxyError{statusCode: http.StatusBadRequest, message: "Scheme must be HTTP"}
	}
	//fmt.Fprintf(w, "Hello Go HTTP")
	var outboundUri = r.RequestURI
	if isTLS(r.Header) {
		outboundUri = strings.Replace(outboundUri, "http", "https", 1)
	}
	outboundRequest, err := http.NewRequest(r.Method, outboundUri, r.Body)
	if err != nil {
		return nil, err
	}
	copyHeaders(r.Header, outboundRequest.Header)
	outboundRequest.Header["User-Agent"] = []string{"Webhook Sentry/0.1"}
	return m.roundTripper.RoundTrip(outboundRequest)
}

func handleError(w http.ResponseWriter, err error) int {
	switch v := err.(type) {
	case *proxyError:
		http.Error(w, v.message, int(v.statusCode))
		return int(v.statusCode)
	default:
		log.Warnf("Unexpected error while proxying request: %s\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
}

func logRequest(r *http.Request, responseCode int) {
	requestLogger := log.WithFields(log.Fields{"client_ip": r.RemoteAddr, "method": r.Method, "url": r.RequestURI, "response_code": responseCode})
	requestLogger.Infoln()
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
	dialer        *net.Dialer
	cidrBlacklist []net.IPNet
}

func (s *safeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := s.dialer.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var chosenIP net.IP = nil
	for _, ip := range ips {
		if strings.Count(ip.IP.String(), ":") < 2 {
			chosenIP = ip.IP
			break
		}
	}
	if chosenIP == nil {
		//return nil, fmt.Errorf("Target %s did not resolve to a valid IPv4 address", addr)
		return nil, &proxyError{statusCode: http.StatusBadRequest, message: fmt.Sprintf("Target %s did not resolve to a valid IPv4 address", addr)}
	}
	if isBlacklisted(s.cidrBlacklist, chosenIP) {
		return nil, &proxyError{statusCode: http.StatusForbidden, message: fmt.Sprintf("Blacklisted IP %s", chosenIP.String())}
	}

	ipPort := net.JoinHostPort(chosenIP.String(), port)
	return s.dialer.DialContext(ctx, "tcp4", ipPort)
}

func isBlacklisted(cidrBlacklist []net.IPNet, ip net.IP) bool {
	if cidrBlacklist == nil {
		return false
	}
	for _, cidr := range cidrBlacklist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

type proxyError struct {
	statusCode uint
	message    string
}

func (p *proxyError) Error() string {
	return fmt.Sprintf("%s, Status code: %d", p.message, p.statusCode)
}

func isTruish(val string) bool {
	if val == "" {
		return false
	}
	return val == "1" || strings.EqualFold(val, "true")
}
