package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type Mitmer struct {
	dialContext          func(ctx context.Context, network, addr string) (net.Conn, error)
	issuerCertificate    *x509.Certificate
	issuerPrivateKey     crypto.PrivateKey
	generatedCertKeyPair *rsa.PrivateKey
}

func NewMitmer() (*Mitmer, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Mitmer{generatedCertKeyPair: keyPair}, nil
}

func (m *Mitmer) HandleHttpConnect(w http.ResponseWriter, r *http.Request) {
	// TODO: think about what context deadlines to set etc
	outboundConn, err := m.dialContext(context.Background(), "tcp4", r.RequestURI)
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

	m.doMitm(inboundConn, outboundConn, r.URL.Hostname())
}

func (m *Mitmer) doMitm(inboundConn net.Conn, outboundConn net.Conn, hostnameInRequest string) {
	var remoteHostname string
	config := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := clientHello.ServerName
			log.Infof("Server name in client hello is %s\n", sni)
			if sni == "" {
				remoteHostname = hostnameInRequest
			} else {
				if sni != hostnameInRequest {
					log.Warnf("SNI name %s in TLS ClientHello is not the same as hostname %s indicated in HTTP CONNECT, proceeding anyway", sni, hostnameInRequest)
				}
				remoteHostname = sni
			}
			return m.generateCert(remoteHostname)
		},
	}
	inboundTLSConn := tls.Server(inboundConn, config)
	defer inboundTLSConn.Close()
	err := inboundTLSConn.Handshake()
	if err != nil {
		log.Errorf("Handshake failed with error %s\n", err)
		return
	}
	/*
		writer := bufio.NewWriter(tlsConn)
		writer.WriteString("HTTP/1.1 200 OK\r\n")
		writer.WriteString("Connection: Close\r\n")
		writer.WriteString("\r\n")
		writer.WriteString("You are MITMed")
		writer.Flush()
	*/
	// NOTE: remoteHostname will only be set after the inbound handshake is done, so we can't do
	// inbound and outbound handshakes in parallel
	// TODO: this is skipping mutual auth, should probably re-use safeDialer, but this will mean we delay
	// TODO: outbound connection establishment until now
	outboundTLSConfig := &tls.Config{
		ServerName: remoteHostname,
	}
	outboundTLSConn := tls.Client(outboundConn, outboundTLSConfig)
	defer outboundTLSConn.Close()
	err = outboundTLSConn.Handshake()
	if err != nil {
		log.Errorf("TLS Handshake failed on outbound connection: %s\n", err)
		return
	}
	go rawProxy(inboundTLSConn, outboundTLSConn)
	rawProxy(outboundTLSConn, inboundTLSConn)
}

// Heavily inspired by generate_cert.go
func (m *Mitmer) generateCert(hostname string) (*tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(time.Duration(-1) * time.Hour)
	notAfter := time.Now().Add(time.Duration(1) * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, m.issuerCertificate, publicKey(m.generatedCertKeyPair), m.issuerPrivateKey)
	if err != nil {
		return nil, err
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	// TODO: this can be done during initialization
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(m.generatedCertKeyPair)
	if err != nil {
		return nil, err
	}
	privKeyPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	cert, err := tls.X509KeyPair(certPemBytes, privKeyPemBytes)
	return &cert, err
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
