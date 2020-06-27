package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const defaultConfig = `
cidrDenyList: ["127.0.0.1/8"]
listeners:
  - type: http
    address: ":9090"
connectTimeout: 10s
connectionLifetime: 60s
readTimeout: 10s
insecureSkipCertVerification: false
insecureSkipCidrDenyList: false
maxResponseBodySize: 1048576
`

type Cidr net.IPNet

type ProxyConfig struct {
	CidrDenyList                 []Cidr                     `yaml:"cidrDenyList"`
	Listeners                    []ListenerConfig           `yaml:"listeners"`
	ConnectTimeout               time.Duration              `yaml:"connectTimeout"`
	ConnectionLifetime           time.Duration              `yaml:"connectionLifetime"`
	ReadTimeout                  time.Duration              `yaml:"readTimeout"`
	MaxResponseBodySize          uint32                     `yaml:"maxResponseBodySize"`
	InsecureSkipCertVerification bool                       `yaml:"insecureSkipCertVerification"`
	InsecureSkipCidrDenyList     bool                       `yaml:"insecureSkipCidrDenyList"`
	ClientCertFile               string                     `yaml:"clientCertFile"`
	ClientKeyFile                string                     `yaml:"clientKeyFile"`
	ClientCerts                  map[string]tls.Certificate `yaml:"-"`
	RootCACerts                  *x509.CertPool             `yaml:"-"` // TODO: not taking a file override yet
	MitmIssuerCertFile           string                     `yaml:"mitmIssuerCertFile"`
	MitmIssuerKeyFile            string                     `yaml:"mitmIssuerKeyFile"`
	MitmIssuerCert               *tls.Certificate           `yaml:"-"`
}

type Protocol string

const (
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
)

type ListenerConfig struct {
	Address  string
	Type     Protocol
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

func (cidr *Cidr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var cidrStr string
	if err := unmarshal(&cidrStr); err != nil {
		return err
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	*cidr = (Cidr)(*ipNet)
	return nil
}

func (config *ProxyConfig) validate() error {
	if err := validateListeners(config.Listeners); err != nil {
		return err
	}
	return nil
}

func validateListeners(listeners []ListenerConfig) error {
	for _, l := range listeners {
		if l.Type != HTTP && l.Type != HTTPS {
			return fmt.Errorf("Invalid listener type %s; must be one of 'http' or 'https'", l.Type)
		}
		if err := validateAddress(l.Address); err != nil {
			return err
		}
		if l.Type == HTTPS && (l.CertFile == "" || l.KeyFile == "") {
			return fmt.Errorf("Both certificate file and private key file must be specified for listener %s", l.Address)
		}
	}
	return nil
}

func validateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("Invalid listener address %s; %s", address, err)
	}
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("Invalid listener address %s; it should be in the format IP:Port", address)
		}
		if strings.Count(ip.String(), ":") > 0 {
			return fmt.Errorf("Invalid listener address %s; only IPv4 addresses are supported", address)
		}
	}
	return nil
}

func (p *ProxyConfig) loadClientCert() error {
	p.ClientCerts = make(map[string]tls.Certificate)
	cert, err := loadCert(p.ClientCertFile, p.ClientKeyFile, "client")
	if err != nil {
		return err
	}
	if cert != nil {
		p.ClientCerts["default"] = *cert
	}
	return nil
}

func (p *ProxyConfig) loadMitmIssuerCert() error {
	cert, err := loadCert(p.MitmIssuerCertFile, p.MitmIssuerKeyFile, "mitmIssuer")
	if err != nil {
		return err
	}
	if cert != nil {
		p.MitmIssuerCert = cert
	}
	return nil
}

func loadCert(certFile string, keyFile string, certName string) (*tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	} else if certFile != "" && keyFile == "" {
		return nil, fmt.Errorf("%sKeyFile must also be specified if %sCertFile is", certName, certName)
	} else if certFile == "" && keyFile != "" {
		return nil, fmt.Errorf("%sCertFile must also be specified if %sKeyFile is", certName, certName)
	} else {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("Error loading %s certificate: %s", certName, err)
		}
		return &cert, err
	}
}

func getRootCABundle() (*x509.CertPool, error) {
	resp, err := http.Get("https://curl.haxx.se/ca/cacert.pem")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	pemBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	rootCerts := x509.NewCertPool()
	if !rootCerts.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("Failed to append certs from downloaded PEM")
	}
	return rootCerts, nil
}

func UnmarshalConfigFromFile(configFile string) (*ProxyConfig, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading file %s: %s", configFile, err)
	}
	return UnmarshalConfig(configData)
}

func UnmarshalConfig(configData []byte) (*ProxyConfig, error) {
	config := NewDefaultConfig()
	if err := yaml.UnmarshalStrict(configData, config); err != nil {
		return nil, fmt.Errorf("Malformed yaml: %s", err)
	}
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Invalid configuration: %s", err)
	}
	if err := config.loadClientCert(); err != nil {
		return nil, err
	}
	if err := config.loadMitmIssuerCert(); err != nil {
		return nil, err
	}
	rootCerts, err := getRootCABundle()
	if err != nil {
		return nil, fmt.Errorf("Error downloading root CA bundle: %s", err)
	}
	config.RootCACerts = rootCerts
	return config, nil
}

func NewDefaultConfig() *ProxyConfig {
	var config ProxyConfig
	if err := yaml.UnmarshalStrict([]byte(defaultConfig), &config); err != nil {
		panic(err)
	}
	return &config
}
