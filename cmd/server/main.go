package main

import (
	"flag"
	"fmt"
	"log"
	"vt-scanner/internal/server"
)

func main() {
	addr := flag.String("addr", ":8000", "Server address (e.g., :8000)")
	cert := flag.String("cert", "", "TLS certificate file (optional)")
	key := flag.String("key", "", "TLS key file (optional)")
	flag.Parse()

	err := server.Run(*addr, *cert, *key)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
	fmt.Println("Server stopped")
}