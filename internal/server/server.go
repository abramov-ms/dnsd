package server

import (
	"fmt"
	"log"
	"net"
)

type Server struct {
	conn *net.UDPConn
}

func New(host string, port int) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Server{conn}, nil
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
