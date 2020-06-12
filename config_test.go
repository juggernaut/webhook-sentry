package main

import (
	"strings"
	"testing"
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

func TestAddressValidation(t *testing.T) {

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
}

func TestYaml(t *testing.T) {
	var data = `
cidrDenyList: ["9.9.9.9", "172.0.0.1/24"]
listeners:
  - type: http
    address: ":12090"
`

	_, err := UnmarshalConfig([]byte(data))
	checkNoError(t, err)
}
