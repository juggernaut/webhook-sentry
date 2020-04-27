package main

import (
	"net/http"
	"testing"
)

func TestCopyHeadersSkipProxyConnection(t *testing.T) {
	inHeaders := make(map[string][]string)
	inHeaders["Proxy-Connection"] = []string{"Keep-Alive"}
	inHeaders["Content-Length"] = []string{"100"}
	outHeaders := make(map[string][]string)
	outHeaders["Connection"] = []string{"Close"}
	copyHeaders(inHeaders, outHeaders)
	_, ok := outHeaders["Proxy-Connection"]
	if ok {
		t.Error("Proxy-Connection erroneously copied")
	}
	cl, ok := outHeaders["Content-Length"]
	if !ok {
		t.Error("Content-Length not copied over")
	}
	if len(cl) != 1 {
		t.Errorf("Expected number of Content-Length header values was 1, got %d", len(cl))
	}
	clVal := cl[0]
	if clVal != "100" {
		t.Errorf("Expected Content-Length value of 100, got %s", clVal)
	}
	_, ok = outHeaders["Connection"]
	if !ok {
		t.Error("Connection header erroneously removed")
	}
}

func TestCopyHeadersSkipWHSentryHeaders(t *testing.T) {
	inHeaders := make(map[string][]string)
	inHeaders[http.CanonicalHeaderKey("X-WhSentry-TLS")] = []string{"true"}
	inHeaders[http.CanonicalHeaderKey("X-WhSentry-Foo")] = []string{"bar"}
	outHeaders := make(map[string][]string)
	outHeaders["Connection"] = []string{"Close"}
	copyHeaders(inHeaders, outHeaders)
	if len(outHeaders) != 1 {
		t.Errorf("Expected to skip X-Wh headers but weren't skipped")
	}
	_, ok := outHeaders["Connection"]
	if !ok {
		t.Error("Connection header erroneously removed")
	}
}
