/**
* Copyright (c) 2020 Ameya Lokare
*/
package proxy

import (
	"strings"
	"testing"
	"time"
)

func checkNoError(t *testing.T, e error) {
	if e != nil {
		t.Fatalf("Expected no error, but found error %s\n", e)
	}
}

func assertError(t *testing.T, msg string, e error) {
	if !strings.Contains(e.Error(), msg) {
		t.Fatalf("Expected error message '%s' to contained string '%s'", e.Error(), msg)
	}
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("Expected %s to be equal to %s\n", a, b)
	}
}

func assertNotNil(t *testing.T, a interface{}, name string) {
	if a == nil {
		t.Fatalf("Expected %s to be non-nil, but was nil\n", name)
	}
}

func TestListenerValidation(t *testing.T) {

	t.Run("Port only is valid", func(t *testing.T) {
		checkNoError(t, validateAddress(":9090"))
	})

	t.Run("IP port is valid", func(t *testing.T) {
		checkNoError(t, validateAddress("127.0.0.1:9090"))
	})

	t.Run("Hostname is not valid", func(t *testing.T) {
		assertError(t, "should be in the format IP:Port", validateAddress("foohost:9090"))
	})

	t.Run("IPv6 is not valid", func(t *testing.T) {
		assertError(t, "only IPv4 addresses are supported", validateAddress("[2001:db8::68]:11090"))
	})

	t.Run("HTTPS needs both certFile and keyFile", func(t *testing.T) {
		listener := ListenerConfig{
			Type:     HTTPS,
			Address:  ":9091",
			CertFile: "/etc/pki/cert",
		}
		err := validateListeners([]ListenerConfig{listener})
		assertError(t, "Both certificate file and private key file", err)
	})
}

func TestYaml(t *testing.T) {

	t.Run("Defaults", func(t *testing.T) {
		config := NewDefaultConfig()
		assertEqual(t, 1, len(config.Listeners))
		listener := config.Listeners[0]
		assertEqual(t, HTTP, listener.Type)
		assertEqual(t, ":9090", listener.Address)
		assertEqual(t, time.Duration(10)*time.Second, config.ConnectTimeout)
		assertEqual(t, false, config.InsecureSkipCertVerification)
		assertEqual(t, false, config.InsecureSkipCidrDenyList)
	})

	t.Run("Override config", func(t *testing.T) {
		var data = `
cidrDenyList: ["9.9.9.9/32", "172.0.0.1/24"]
listeners:
  - type: http
    address: ":12090"
`
		config, err := UnmarshalConfig([]byte(data))
		checkNoError(t, err)
		assertNotNil(t, config.CidrDenyList, "CidrDenyList")
		assertEqual(t, 2, len(config.CidrDenyList))
		assertEqual(t, 1, len(config.Listeners))
		listener := config.Listeners[0]
		assertEqual(t, HTTP, listener.Type)
		assertEqual(t, ":12090", listener.Address)

		// test defaults set for parameters that aren't overridden
		assertEqual(t, time.Duration(10)*time.Second, config.ConnectTimeout)
	})
}
