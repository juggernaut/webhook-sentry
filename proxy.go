package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

var skipHeaders = []string{"Connection", "Proxy-Connection", "User-Agent"}

func main() {
	fmt.Printf("Hello egress proxy\n")
	var config *ProxyConfig
	if len(os.Args) > 1 {
		var err error
		config, err = UnmarshalConfigFromFile(os.Args[1])
		if err != nil {
			log.Fatalf("Failed to unmarshal config from file %s: %s\n", os.Args[1], err)
		}
	} else {
		config = NewDefaultConfig()
	}
	setupLogging()
	proxyServers := CreateProxyServers(config)
	wg := &sync.WaitGroup{}
	for i, proxyServer := range proxyServers {
		wg.Add(1)
		listenerConfig := config.Listeners[i]
		if listenerConfig.Type == HTTP {
			startHTTPServer(listenerConfig.Address, proxyServer, wg)
		} else {
			startTLSServer(listenerConfig.Address, listenerConfig.CertFile, listenerConfig.KeyFile, proxyServer, wg)
		}
	}
	wg.Wait()
}

func setupLogging() {
	if isTruish(os.Getenv("TRACE")) {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

func startHTTPServer(listenAddress string, server *http.Server, wg *sync.WaitGroup) {
	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		log.Fatalf("Could not start egress proxy HTTP listener: %s\n", err)
	}
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("Failed to start proxy HTTP server: %s\n", err)
		}
		wg.Done()
	}()
}

func startTLSServer(listenAddress, certFile, keyFile string, server *http.Server, wg *sync.WaitGroup) {
	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		log.Fatalf("Could not start egress proxy HTTPS listener: %s\n", err)
	}
	go func() {
		if err := server.ServeTLS(listener, certFile, keyFile); err != http.ErrServerClosed {
			log.Fatalf("Failed to start proxy HTTPS server: %s\n", err)
		}
		wg.Done()
	}()
}

func CreateProxyServers(proxyConfig *ProxyConfig) []*http.Server {

	sd := newSafeDialer(proxyConfig)
	transport := &http.Transport{
		Proxy:              nil,
		IdleConnTimeout:    time.Duration(20) * time.Second,
		DisableKeepAlives:  true,
		DisableCompression: true,
		DialContext:        sd.DialContext,
		DialTLSContext:     sd.DialTLSContext,
	}

	var proxyServers []*http.Server
	for _, listenerConfig := range proxyConfig.Listeners {
		proxyServers = append(proxyServers, newProxyServer(listenerConfig, proxyConfig, sd, transport))
	}
	return proxyServers
}

func newProxyServer(listenerConfig ListenerConfig, proxyConfig *ProxyConfig, sd *safeDialer, rt http.RoundTripper) *http.Server {
	handler := &ProxyHTTPHandler{
		roundTripper:               rt,
		dialContext:                sd.DialContext,
		outboundConnectionLifetime: proxyConfig.ConnectionLifetime,
		idleReadTimeout:            proxyConfig.ReadTimeout,
		maxContentLength:           proxyConfig.MaxResponseBodySize,
	}
	return &http.Server{
		Addr:           listenerConfig.Address,
		Handler:        handler,
		ConnState:      handler.connStateCallback,
		MaxHeaderBytes: 1 << 20,
	}
}

// ProxyHTTPHandler some struct
type ProxyHTTPHandler struct {
	roundTripper               http.RoundTripper
	dialContext                func(ctx context.Context, network, addr string) (net.Conn, error)
	outboundConnectionLifetime time.Duration
	idleReadTimeout            time.Duration
	currentInboundConns        uint32
	maxContentLength           uint32
}

func (p *ProxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		ctx, cancel := context.WithTimeout(context.TODO(), p.outboundConnectionLifetime)
		defer cancel()
		start := time.Now()
		resp, err := p.doProxy(ctx, r)
		if resp != nil {
			defer resp.Body.Close()
		}
		var responseCode int
		if err != nil {
			responseCode = handleError(w, err)
		} else if resp.ContentLength > 0 && uint32(resp.ContentLength) > p.maxContentLength {
			responseCode = http.StatusBadGateway
			http.Error(w, "Response exceeds max content length", responseCode)
		} else {
			responseCode = resp.StatusCode
			writeResponseHeaders(w, resp)
			p.writeResponseBody(w, resp, cancel)
		}
		duration := time.Now().Sub(start)
		logRequest(r, responseCode, duration)
	}
}

func (p *ProxyHTTPHandler) connStateCallback(conn net.Conn, connState http.ConnState) {
	// NOTE: Hijacked connections do not transition to closed
	if connState == http.StateNew {
		p.incrementInboundConns()
	} else if connState == http.StateClosed {
		p.decrementInboundConns()
	}
}

func (p *ProxyHTTPHandler) incrementInboundConns() {
	updatedInboundConns := atomic.AddUint32(&p.currentInboundConns, 1)
	log.Tracef("New inbound connection opened; current inbound connections = %d\n", updatedInboundConns)
}

func (p *ProxyHTTPHandler) decrementInboundConns() {
	updatedInboundConns := atomic.AddUint32(&p.currentInboundConns, ^uint32(0))
	log.Tracef("Inbound connection closed; current inbound connections = %d\n", updatedInboundConns)
}

func writeResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, values := range resp.Header {
		w.Header().Set(k, values[0])
		for _, v := range values[1:] {
			w.Header().Add(k, v)
		}
	}
	if resp.TransferEncoding != nil {
		for _, t := range resp.TransferEncoding {
			w.Header().Add("Transfer-Encoding", t)
		}
	}
	w.WriteHeader(resp.StatusCode)
}

func (p *ProxyHTTPHandler) writeResponseBody(w http.ResponseWriter, resp *http.Response, cancel context.CancelFunc) {
	defer resp.Body.Close()
	// XXX: pick optimal buffer size
	buf := make([]byte, 512)
	timer := time.AfterFunc(p.idleReadTimeout, func() {
		cancel()
	})
	var bytesReadSoFar uint32 = 0
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			bytesReadSoFar += uint32(n)
			//log.Infof("Bytes read so far = %d", bytesReadSoFar)
			if bytesReadSoFar > p.maxContentLength {
				log.Warn("Response body exceeded maximum allowed length")
				break
			}
			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				log.Warnf("Error writing to inbound socket: %s\n", writeErr)
				break
			}
		}
		if err == io.EOF {
			break
		} else if err == context.Canceled {
			log.Info("Socket idle read time out reached")
			break
		} else if err != nil {
			log.Warnf("error occured reading response: %s\n", err)
			break
		}
		timer.Reset(p.idleReadTimeout)
	}
}

func (p *ProxyHTTPHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	// TODO: think about what context deadlines to set etc
	outboundConn, err := p.dialContext(context.Background(), "tcp4", r.RequestURI)
	if err != nil {
		handleError(w, err)
		return
	}
	defer outboundConn.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Connection hijacking not supported", http.StatusInternalServerError)
		return
	}
	inboundConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer inboundConn.Close()
	bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n")
	bufrw.WriteString("Connection: Close\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	go rawProxy(inboundConn, outboundConn)
	rawProxy(outboundConn, inboundConn)
}

func rawProxy(inConn net.Conn, outConn net.Conn) {
	defer inConn.Close()
	defer outConn.Close()
	buf := make([]byte, 2048)
	for {
		numRead, err := inConn.Read(buf)
		if numRead > 0 {
			_, writeErr := outConn.Write(buf[:numRead])
			// Write must return a non-nil error if it returns n < len(p)
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

type key int

const clientCertKey key = 0

func (p ProxyHTTPHandler) doProxy(ctx context.Context, r *http.Request) (*http.Response, error) {
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
	clientCert, ok := r.Header["X-Whsentry-Clientcert"]
	if ok && len(clientCert) > 0 {
		ctx = context.WithValue(ctx, clientCertKey, clientCert[0])
	}
	outboundRequest, err := http.NewRequestWithContext(ctx, r.Method, outboundUri, r.Body)
	if err != nil {
		return nil, err
	}
	copyHeaders(r.Header, outboundRequest.Header)
	outboundRequest.Header["User-Agent"] = []string{"Webhook Sentry/0.1"}
	return p.roundTripper.RoundTrip(outboundRequest)
}

func handleError(w http.ResponseWriter, err error) int {
	switch v := err.(type) {
	case *proxyError:
		// TODO: handle failure of http.Error
		http.Error(w, v.message, int(v.statusCode))
		return int(v.statusCode)
	case net.Error:
		if v.Timeout() {
			http.Error(w, "Request to target timed out", http.StatusBadGateway)
			return http.StatusBadGateway
		} else {
			log.Warnf("Unexpected error while proxying request: %s\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return http.StatusInternalServerError
		}
	case x509.CertificateInvalidError, x509.HostnameError:
		http.Error(w, v.Error(), http.StatusBadGateway)
		return http.StatusBadGateway
	default:
		log.Warnf("Unexpected error while proxying request: %s\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
}

func logRequest(r *http.Request, responseCode int, responseTime time.Duration) {
	requestLogger := log.WithFields(log.Fields{"client_ip": r.RemoteAddr, "method": r.Method, "url": r.RequestURI, "response_code": responseCode,
		"response_time": responseTime})
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
	dialer                     *net.Dialer
	cidrBlacklist              []net.IPNet
	clientCerts                map[string]tls.Certificate
	skipServerCertVerification bool
	rootCerts                  *x509.CertPool
}

func newSafeDialer(config *ProxyConfig) *safeDialer {
	dialer := &net.Dialer{
		Timeout:   config.ConnectTimeout,
		DualStack: false,
		KeepAlive: -1,
	}
	var cidrDenyList []net.IPNet
	if !config.InsecureSkipCidrDenyList {
		for _, cidr := range config.CidrDenyList {
			cidrDenyList = append(cidrDenyList, net.IPNet(cidr))
		}
	}
	return &safeDialer{
		dialer:                     dialer,
		cidrBlacklist:              cidrDenyList,
		skipServerCertVerification: config.InsecureSkipCidrDenyList,
		clientCerts:                config.ClientCerts,
		rootCerts:                  config.RootCACerts,
	}
}

func (s *safeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ipPort, err := s.resolveIPPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return s.dialer.DialContext(ctx, "tcp4", ipPort)
}

func (s *safeDialer) resolveIPPort(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	ips, err := s.dialer.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
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
		return "", &proxyError{statusCode: http.StatusBadRequest, message: fmt.Sprintf("Target %s did not resolve to a valid IPv4 address", addr)}
	}
	if isBlacklisted(s.cidrBlacklist, chosenIP) {
		return "", &proxyError{statusCode: http.StatusForbidden, message: fmt.Sprintf("Blacklisted IP %s", chosenIP.String())}
	}

	return net.JoinHostPort(chosenIP.String(), port), nil
}

func (s *safeDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	certAlias, ok := ctx.Value(clientCertKey).(string)
	var getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	if ok {
		cert, ok := s.clientCerts[certAlias]
		if !ok {
			return nil, &proxyError{statusCode: http.StatusInternalServerError, message: "Programming error: Cert alias existence should have been checked upstack"}
		}
		getClientCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}
	// We need the host here to set the SNI hostname, otherwise it incorrectly uses the IP address as the SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:           host,
		InsecureSkipVerify:   s.skipServerCertVerification,
		GetClientCertificate: getClientCert,
		RootCAs:              s.rootCerts,
	}

	ipPort, err := s.resolveIPPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return tls.DialWithDialer(s.dialer, "tcp4", ipPort, tlsConfig)
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
