package main

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
	"math/big"
	"net"
	"time"
)

func generateKeyPair() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func generateCertificate(hostname string, key crypto.PrivateKey, notBefore time.Time, notAfter time.Time, issuerCertificate *x509.Certificate, issuerPrivateKey crypto.PrivateKey, isClientCert bool, isCA bool) ([]byte, error) {

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

	extKeyUsage := x509.ExtKeyUsageServerAuth
	if isClientCert {
		extKeyUsage = x509.ExtKeyUsageClientAuth
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
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

	return x509.CreateCertificate(rand.Reader, &template, issuerTemplate, publicKey(key), issuerPrivateKey)
}

func generateRootCACert() (crypto.PrivateKey, *x509.Certificate, error) {
	key, err := generateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now().Add(time.Duration(-1) * time.Hour)
	notAfter := time.Now().Add(time.Duration(1) * time.Hour)
	certBytes, err := generateCertificate("wh-sentry-root.com", key, notBefore, notAfter, nil, nil, false, true)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func generateLeafCert(hostname string, issuerCert *x509.Certificate, issuerKey crypto.PrivateKey, isClient bool) (*tls.Certificate, error) {
	key, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(time.Duration(-1) * time.Minute)
	notAfter := time.Now().Add(time.Duration(30) * time.Minute)

	derBytes, err := generateCertificate(hostname, key, notBefore, notAfter, issuerCert, issuerKey, isClient, false)
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

func x509ToTLSCertificate(x509Cert *x509.Certificate, privateKey crypto.PrivateKey) (*tls.Certificate, error) {
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.Raw})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privKeyPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	cert, err := tls.X509KeyPair(certPemBytes, privKeyPemBytes)
	return &cert, err
}
