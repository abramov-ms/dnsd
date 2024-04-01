package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type Server struct {
	db   Db
	conn *net.UDPConn
}

func NewServer(db Db, host string, port int) (*Server, error) {
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
		_, addr, err := s.conn.ReadFromUDP(buffer[:])
		if err != nil {
			log.Println("Error reading from UDP socket: ", err)
			continue
		}

		log.Printf("Got request from %v\n", *addr)
		request, _ := ParseMessage(buffer[:])

		var response Message
		response.Header = &Header{}
		response.Header.Response = true
		response.Header.ID = request.Header.ID
		response.Header.OpCode = request.Header.OpCode
		response.Question = make([]Question, 0)
		response.Authority = make([]Record, 0)
		response.Answer = make([]Record, 0)
		response.Additional = make([]Record, 0)

		for _, q := range request.Question {
			if q.QType != QType(A) || q.QClass != QClass(IN) {
				response.Header.RCode = NotImplemented
				response.Put(buffer[:])
				s.conn.WriteToUDP(buffer[:], addr)
			} else {
				domain := strings.Join(q.Name, ".")
				record, ok := s.db[domain]
				if ok {
					response.Answer = append(response.Answer, *record)
					response.Header.AnswerRecords++
				}
			}
		}

		size := response.Put(buffer[:])
		_, err = s.conn.WriteToUDP(buffer[:size], addr)
		if err != nil {
			log.Println("Error writing to UDP socket: ", err)
			continue
		}

		log.Printf("%v's request served\n", *addr)
	}
}
