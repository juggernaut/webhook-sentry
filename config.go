package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type ProxyConfig struct {
	CidrDenyList       []string
	Listeners          []ListenerConfig
	ConnectionLifetime time.Duration
	ReadTimeout        time.Duration
}

type Protocol string

const (
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
)

type ListenerConfig struct {
	Address string
	Type    Protocol
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

func UnmarshalConfigFromFile(configFile string) (*ProxyConfig, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading file %s: %s", configFile, err)
	}
	return UnmarshalConfig(configData)
}

func UnmarshalConfig(configData []byte) (*ProxyConfig, error) {
	config := ProxyConfig{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("Malformed yaml: %s", err)
	}
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Invalid configuration: %s", err)
	}
	return &config, nil
}
