/**
* Copyright (c) 2020 Ameya Lokare
*/
package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/juggernaut/webhook-sentry/proxy"
	"math/big"
	"net"
	"testing"
	"time"
)

func GenerateKeyPair() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GenerateCertificate(hostname string, organizationName string, key crypto.PrivateKey, notBefore time.Time, notAfter time.Time, issuerCertificate *x509.Certificate, issuerPrivateKey crypto.PrivateKey, isClientCert bool, isCA bool) ([]byte, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := key.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var extKeyUsage x509.ExtKeyUsage
	if isCA {
		extKeyUsage = x509.ExtKeyUsageAny
	} else if isClientCert {
		extKeyUsage = x509.ExtKeyUsageClientAuth
	} else {
		extKeyUsage = x509.ExtKeyUsageServerAuth
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organizationName},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{extKeyUsage},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var issuerTemplate *x509.Certificate = issuerCertificate
	if issuerTemplate == nil {
		issuerTemplate = &template
	}

	if issuerPrivateKey == nil {
		issuerPrivateKey = key
	}

	return x509.CreateCertificate(rand.Reader, &template, issuerTemplate, proxy.PublicKey(key), issuerPrivateKey)
}

func GenerateRootCACert() (crypto.PrivateKey, *x509.Certificate, error) {
	key, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now().Add(time.Duration(-1) * time.Hour)
	notAfter := time.Now().Add(time.Duration(1) * time.Hour)
	certBytes, err := GenerateCertificate("wh-sentry-root.com", "WH Sentry Root", key, notBefore, notAfter, nil, nil, true, true)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func GenerateLeafCert(hostname string, organizationName string, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey, isClient bool) (*tls.Certificate, error) {
	key, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(time.Duration(-1) * time.Minute)
	notAfter := time.Now().Add(time.Duration(30) * time.Minute)

	derBytes, err := GenerateCertificate(hostname, organizationName, key, notBefore, notAfter, issuerCert, issuerKey, isClient, false)
	if err != nil {
		return nil, err
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	privKeyPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	cert, err := tls.X509KeyPair(certPemBytes, privKeyPemBytes)
	return &cert, err
}

func X509ToTLSCertificate(x509Cert *x509.Certificate, privateKey crypto.PrivateKey) (*tls.Certificate, error) {
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.Raw})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privKeyPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	cert, err := tls.X509KeyPair(certPemBytes, privKeyPemBytes)
	return &cert, err
}

type CertificateFixtures struct {
	RootCAs                   *x509.CertPool
	RootCAPrivateKey          crypto.PrivateKey
	RootCACert                *tls.Certificate
	ProxyCert                 *tls.Certificate
	ServerCert                *tls.Certificate
	InvalidHostnameServerCert *tls.Certificate
	ClientCert                *tls.Certificate
}

func NewCertificateFixtures(t *testing.T) *CertificateFixtures {
	rootCertKey, rootCert, err := GenerateRootCACert()
	if err != nil {
		t.Fatalf("Error generating root CA cert: %s", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	rootCACert, err := X509ToTLSCertificate(rootCert, rootCertKey)
	if err != nil {
		t.Fatalf("Error converting x509 to TLS certificate: %s", err)
	}

	serverCert, err := GenerateLeafCert("localhost", "WH Sentry Test Server", rootCert, rootCertKey, false)
	if err != nil {
		t.Fatalf("Error generating server cert: %s", err)
	}

	invalidHostnameServerCert, err := GenerateLeafCert("wh-target-server.com", "WH Sentry Test Server", rootCert, rootCertKey, false)
	if err != nil {
		t.Fatalf("Error generating server cert: %s", err)
	}

	proxyCert, err := GenerateLeafCert("127.0.0.1", "WH Sentry Proxy", rootCert, rootCertKey, false)
	if err != nil {
		t.Fatalf("Error generating server cert: %s", err)
	}

	clientCert, err := GenerateLeafCert("wh-client.com", "WH Sentry Client", rootCert, rootCertKey, true)
	if err != nil {
		t.Fatalf("Error generating client cert: %s", err)
	}
	return &CertificateFixtures{
		RootCAs:                   certPool,
		RootCAPrivateKey:          rootCertKey,
		RootCACert:                rootCACert,
		ServerCert:                serverCert,
		InvalidHostnameServerCert: invalidHostnameServerCert,
		ProxyCert:                 proxyCert,
		ClientCert:                clientCert,
	}
}

