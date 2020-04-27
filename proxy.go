package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

var skipHeaders = [...]string{"Connection", "Proxy-Connection", "User-Agent"}

func main() {
	fmt.Printf("Hello egress proxy\n")
	tr := &http.Transport{
		Proxy:             nil,
		IdleConnTimeout:   20000,
		DisableKeepAlives: true,
	}
	server := &http.Server{
		Addr:           ":9090",
		Handler:        ProxyHTTPHandler{roundTripper: tr},
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

// some struct
type ProxyHTTPHandler struct {
	roundTripper http.RoundTripper
}

func (m ProxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Host is %s\n", r.Host)
	log.Printf("URL is %s\n", r.URL.String())
	if !r.URL.IsAbs() {
		http.Error(w, "Request URI must be absolute", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "Scheme must be HTTP", http.StatusBadRequest)
		return
	}
	//fmt.Fprintf(w, "Hello Go HTTP")
	var outboundUri = r.RequestURI
	if isTLS(r) {
		outboundUri = strings.Replace(outboundUri, "http", "https", 1)
	}
	outboundRequest, err := http.NewRequest(r.Method, outboundUri, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	copyHeaders(r, outboundRequest)
	resp, err := m.roundTripper.RoundTrip(outboundRequest)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	resp.Write(w)
}

func isTLS(r *http.Request) bool {
	tlsHeader, ok := r.Header["X-Whsentry-Tls"]
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

func copyHeaders(clientRequest *http.Request, serverRequest *http.Request) {
	for name, values := range clientRequest.Header {
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
				serverRequest.Header.Add(name, value)
			}
		}
	}
}
