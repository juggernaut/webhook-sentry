package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

func main() {
	fmt.Printf("Hello egress proxy\n")
	tr := &http.Transport{
		IdleConnTimeout:   20000,
		DisableKeepAlives: true,
	}
	client := http.Client{Transport: tr}
	server := &http.Server{
		Addr:           ":9090",
		Handler:        MyHttpHandler{client: client},
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

// some struct
type MyHttpHandler struct {
	client http.Client
}

func (m MyHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Host is %s\n", r.Host)
	log.Printf("URL is %s\n", r.URL.String())
	//fmt.Fprintf(w, "Hello Go HTTP")
	outboundRequest, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	resp, err := m.client.Do(outboundRequest)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	resp.Write(w)
}

func echoConnection(conn net.Conn) {
	b := make([]byte, 20)
	for {
		n, err := conn.Read(b)
		if err != nil {
			fmt.Println(err)
			conn.Close()
			return
		}
		if n > 0 {
			_, err := conn.Write(b[:n])
			if err != nil {
				fmt.Println(err)
				conn.Close()
				return
			}
		}
	}
}
