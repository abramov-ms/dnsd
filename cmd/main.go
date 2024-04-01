package main

import (
	"dnsd/internal/dns"
	"dnsd/internal/server"
	"flag"
	"log"
)

const (
	DefaultHost = "127.0.0.1"
	DefaultPort = 53
)

var (
	dbFlag   = flag.String("db", "", "DNS database file")
	hostFlag = flag.String("host", DefaultHost, "Host to listen to UDP requests on")
	portFlag = flag.Int("port", DefaultPort, "UDP port to listen to DNS requests on")
)

func main() {
	flag.Parse()

	db, err := dns.ImportDb(*dbFlag)
	if err != nil {
		log.Fatalln(err)
	}

	server, err := server.New(db, *hostFlag, *portFlag)
	if err != nil {
		log.Fatalln(err)
	}

	server.Run()
}
