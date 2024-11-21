package main

import (
	"fmt"
	"net"
	"os"
)

func client() {
	// Connect to the Unix domain socket
	conn, err := net.Dial("unix", "/var/run/fstrace.sock")
	if err != nil {
		fmt.Println("dial error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send a message
	_, err = conn.Write([]byte("Hello from client!\n"))
	if err != nil {
		fmt.Println("write error:", err)
		return
	}

	// Read the response
	var buf [512]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		fmt.Println("read error:", err)
		return
	}

	fmt.Printf("Received message: %s\n", string(buf[:n]))
}
