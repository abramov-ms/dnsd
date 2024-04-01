package main

import (
	"dnsd/internal/server"
	"flag"
	"log"
)

const (
	DefaultHost = "127.0.0.1"
	DefaultPort = 53
)

var (
	hostFlag = flag.String("host", DefaultHost, "Host to listen to UDP requests on")
	portFlag = flag.Int("port", DefaultPort, "UDP port to listen to DNS requests on")
)

func main() {
	flag.Parse()

	server, err := server.New(*hostFlag, *portFlag)
	if err != nil {
		log.Fatalln(err)
	}

	server.Run()
}
