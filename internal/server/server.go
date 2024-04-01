package server

import (
	"dnsd/internal/dns"
	"fmt"
	"log"
	"net"
)

type Server struct {
	db   dns.Db
	conn *net.UDPConn
}

func New(db dns.Db, host string, port int) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Server{db, conn}, nil
}

func (s Server) Run() {
	for {
		var buffer [1024]byte
		bytes, addr, err := s.conn.ReadFromUDP(buffer[:])
		if err != nil {
			log.Println("Error reading from UDP socket: ", err)
			continue
		}

		_, err = s.conn.WriteToUDP(buffer[:bytes], addr)
		if err != nil {
			log.Println("Error writing to UDP socket: ", err)
		}
	}
}
