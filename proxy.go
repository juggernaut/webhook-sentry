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

	"github.com/sirupsen/logrus"
)

var skipHeaders = []string{"Connection", "Proxy-Connection", "User-Agent"}

var accessLog = logrus.New()
var log = logrus.New()

const (
	ErrorCodeHeader    string = "X-WhSentry-ErrorCode"
	ErrorMessageHeader string = "X-WhSentry-ErrorMessage"

	BlockedIPAddress  string = "1000"
	UnableToResolveIP string = "1001"
	InvalidRequestURI string = "1002"
	InvalidUrlScheme  string = "1003"
	RequestTimedOut   string = "1004"
	TLSHandshakeError string = "1005"
)

func main() {
	fmt.Print(banner)
	var config *ProxyConfig
	var err error
	if len(os.Args) > 1 {
		config, err = UnmarshalConfigFromFile(os.Args[1])
		if err != nil {
			log.Fatalf("Failed to unmarshal config from file %s: %s\n", os.Args[1], err)
		}
	} else {
		config, err = InitDefaultConfig()
		if err != nil {
			log.Fatalf("Failed to initialize proxy configuration: %s\n", err)
		}
	}
	//setupLogging()
	accessLog.Out = os.Stdout
	accessLog.SetFormatter(&AccessLogTextFormatter{})

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

/*
func setupLogging() {
	if isTruish(os.Getenv("TRACE")) {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}
*/

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

	var mitmer *Mitmer
	var err error
	if proxyConfig.MitmIssuerCert != nil {
		mitmer, err = NewMitmer()
		if err != nil {
			log.Fatalf("Fatal error trying to generate keys for MITM: %s", err)
		}
		mitmer.dialContext = sd.DialContext
		mitmer.doTLSHandshake = sd.doTLSHandshake
		mitmer.issuerPrivateKey = proxyConfig.MitmIssuerCert.PrivateKey
		x509Cert, err := x509.ParseCertificate(proxyConfig.MitmIssuerCert.Certificate[0])
		if err != nil {
			log.Fatalf("Invalid X509 MITM issuer certificate: %s\n", err)
		}
		mitmer.issuerCertificate = x509Cert
	}

	var proxyServers []*http.Server
	for _, listenerConfig := range proxyConfig.Listeners {
		proxyServers = append(proxyServers, newProxyServer(listenerConfig, proxyConfig, sd, transport, mitmer))
	}
	return proxyServers
}

func newProxyServer(listenerConfig ListenerConfig, proxyConfig *ProxyConfig, sd *safeDialer, rt http.RoundTripper, mitmer *Mitmer) *http.Server {
	handler := &ProxyHTTPHandler{
		roundTripper:               rt,
		outboundConnectionLifetime: proxyConfig.ConnectionLifetime,
		idleReadTimeout:            proxyConfig.ReadTimeout,
		maxContentLength:           proxyConfig.MaxResponseBodySize,
		mitmer:                     mitmer,
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
	outboundConnectionLifetime time.Duration
	idleReadTimeout            time.Duration
	currentInboundConns        uint32
	maxContentLength           uint32
	mitmer                     *Mitmer
}

func (p *ProxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// We only allow CONNECT if we have a configured MITM issuer certificate
		if p.mitmer == nil {
			http.Error(w, "CONNECT method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p.mitmer.HandleHttpConnect(w, r)
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
				//log.Warn("Response body exceeded maximum allowed length")
				break
			}
			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				//log.Warnf("Error writing to inbound socket: %s\n", writeErr)
				break
			}
		}
		if err == io.EOF {
			break
		} else if err == context.Canceled {
			//log.Info("Socket idle read time out reached")
			break
		} else if err != nil {
			//log.Warnf("error occured reading response: %s\n", err)
			break
		}
		timer.Reset(p.idleReadTimeout)
	}
}

type key int

const clientCertKey key = 0

func (p ProxyHTTPHandler) doProxy(ctx context.Context, r *http.Request) (*http.Response, error) {
	if !r.URL.IsAbs() {
		return nil, &proxyError{statusCode: http.StatusBadRequest, message: "Request URI must be absolute", errorCode: InvalidRequestURI}
	}
	if r.URL.Scheme != "http" {
		return nil, &proxyError{statusCode: http.StatusBadRequest, message: "URL scheme must be HTTP", errorCode: InvalidUrlScheme}
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
		w.Header().Add(ErrorCodeHeader, v.errorCode)
		w.Header().Add(ErrorMessageHeader, v.message)
		// TODO: handle failure of http.Error
		http.Error(w, v.message, int(v.statusCode))
		return int(v.statusCode)
	case net.Error:
		if v.Timeout() {
			const timedOut string = "Request to target timed out"
			w.Header().Add(ErrorCodeHeader, RequestTimedOut)
			w.Header().Add(ErrorMessageHeader, timedOut)
			http.Error(w, timedOut, http.StatusBadGateway)
			return http.StatusBadGateway
		}
		if opErr, ok := v.(*net.OpError); ok {
			return handleNetOpError(w, *opErr)
		}
		//log.Warnf("Unexpected error while proxying request: %s\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	case x509.CertificateInvalidError, x509.HostnameError:
		http.Error(w, v.Error(), http.StatusBadGateway)
		return http.StatusBadGateway
	default:
		//log.Warnf("Unexpected error while proxying request: %s\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
}

func handleNetOpError(w http.ResponseWriter, err net.OpError) int {
	wrapped := err.Unwrap()
	// This is hacky, but the TLS alert errors aren't exported
	if strings.HasPrefix(wrapped.Error(), "tls:") {
		message := fmt.Sprintf("TLS handshake error: %s", wrapped)
		//log.Infof(message)
		w.Header().Add(ErrorMessageHeader, message)
		w.Header().Add(ErrorCodeHeader, TLSHandshakeError)
		http.Error(w, message, http.StatusBadGateway)
		return http.StatusBadGateway
	}
	//log.Warnf("Unexpected error while proxying request: %s\n", wrapped)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	return http.StatusInternalServerError
}

func logRequest(r *http.Request, responseCode int, responseTime time.Duration) {
	requestLogger := accessLog.WithFields(logrus.Fields{"client_addr": r.RemoteAddr, "method": r.Method, "url": r.RequestURI, "response_code": responseCode,
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
		skipServerCertVerification: config.InsecureSkipCertVerification,
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
		return "", &proxyError{statusCode: http.StatusBadRequest, message: fmt.Sprintf("Target %s did not resolve to a valid IPv4 address", addr), errorCode: UnableToResolveIP}
	}
	if isBlacklisted(s.cidrBlacklist, chosenIP) {
		return "", &proxyError{statusCode: http.StatusForbidden, message: fmt.Sprintf("IP %s is blocked", chosenIP.String()), errorCode: BlockedIPAddress}
	}

	return net.JoinHostPort(chosenIP.String(), port), nil
}

func (s *safeDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// We need the host here to set the SNI hostname, otherwise it incorrectly uses the IP address as the SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ipPort, err := s.resolveIPPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	conn, err := s.dialer.DialContext(ctx, "tcp4", ipPort)
	if err != nil {
		return nil, err
	}
	certAlias, ok := ctx.Value(clientCertKey).(string)
	if ok {
		if _, found := s.clientCerts[certAlias]; !found {
			return nil, &proxyError{statusCode: http.StatusInternalServerError, message: fmt.Sprintf("Programming error; no cert with alias %s, this check should have been made upstack", certAlias)}
		}
	}
	return s.doTLSHandshake(conn, host, certAlias)
}

func (s *safeDialer) doTLSHandshake(conn net.Conn, hostname string, certAlias string) (net.Conn, error) {
	var clientCert tls.Certificate
	if certAlias != "" {
		cert, ok := s.clientCerts[certAlias]
		if ok {
			clientCert = cert
		}
	}
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: s.skipServerCertVerification,
		GetClientCertificate: func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if len(clientCert.Certificate) == 0 {
				//log.Warn("Client certificate requested by server, but we don't have one")
			}
			return &clientCert, nil
		},
		RootCAs: s.rootCerts,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	// NOTE: this effectively makes the total timeout for a TLS conn (2 * Config.Timeout)
	tlsConn.SetDeadline(time.Now().Add(s.dialer.Timeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
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
	errorCode  string
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

type AccessLogTextFormatter struct {
}

func (f *AccessLogTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	fields := entry.Data
	ts := entry.Time.Format(time.RFC3339)
	responseTime := fields["response_time"].(time.Duration)
	logLine := fmt.Sprintf("[%s] %s %s %s %d %dms\n", ts, fields["client_addr"], fields["method"], fields["url"], fields["response_code"], responseTime.Milliseconds())
	return []byte(logLine), nil
}
