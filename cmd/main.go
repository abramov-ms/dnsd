package main

import (
	"dnsd/internal/dns"
	"flag"
	"log"
	"os"
	"sync"
)

const (
	DefaultHost = "127.0.0.1"
	DefaultPort = 53
)

var (
	dbFlag      = flag.String("db", "", "DNS database file")
	hostFlag    = flag.String("host", DefaultHost, "Host to listen to UDP requests on")
	portFlag    = flag.Int("port", DefaultPort, "UDP port to listen to DNS requests on")
	workersFlag = flag.Int("workers", 1, "Number of workers handling requests")
)

func main() {
	flag.Parse()
	if *dbFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	db, err := dns.ImportDb(*dbFlag)
	if err != nil {
		log.Fatalln(err)
	}

	server, err := dns.NewServer(db, *hostFlag, *portFlag)
	if err != nil {
		log.Fatalln(err)
	}

	var wg sync.WaitGroup
	for j := 0; j < *workersFlag; j++ {
		wg.Add(1)
		go func() {
			server.Run()
			wg.Done()
		}()
	}

	wg.Wait()
}
