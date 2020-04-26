package main

import (
	"fmt"
	"net"
)

func main() {
	fmt.Printf("Hello egress proxy\n")
	listener, err := net.Listen("tcp", "127.0.0.1:6080")
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
		} else {
			go echoConnection(conn)
		}

	}
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
