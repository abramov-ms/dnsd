package dns

import (
	"encoding/binary"
)

type OpCode int

const (
	Query OpCode = iota
	InverseQuery
	Status
)

type RCode int

const (
	Ok RCode = iota
	FormatError
	ServerFailure
	NameError
	NotImplemented
	Refused
)

type Header struct {
	ID                  int
	Query               bool
	Opcode              OpCode
	AuthoritativeAnswer bool
	Truncation          bool
	RecursionDesired    bool
	RecursionAvailable  bool
	RCode               RCode
	QuestionRecords     int
	AnswerRecords       int
	NameServerRecords   int
	AddtitionalRecords  int
}

const (
	headerBytes = 12
	idOffset    = 0

	flagsOffset            = 1
	queryBit               = 15
	opcodeOffset           = 11
	opcodeMask             = 1<<4 - 1
	authoritativeAnswerBit = 1 << 10
	truncationBit          = 1 << 9
	recursionDesiredBit    = 1 << 8
	recursionAvailableBit  = 1 << 7
	rcodeMask              = 1<<4 - 1

	questionRecordsOffset    = 4
	answerRecordsOffset      = 6
	nameServerRecordsOffset  = 8
	addtitionalRecordsOffset = 10
)

func ParseHeader(data []byte) (*Header, int) {
	var h Header
	h.ID = int(binary.BigEndian.Uint16(data[idOffset:]))

	flags := binary.BigEndian.Uint16(data[flagsOffset:])
	h.Query = flags&queryBit != 0
	h.Opcode = OpCode((flags >> opcodeOffset) & opcodeMask)
	h.AuthoritativeAnswer = flags&authoritativeAnswerBit != 0
	h.Truncation = flags&truncationBit != 0
	h.RecursionDesired = flags&recursionDesiredBit != 0
	h.RecursionAvailable = flags&recursionAvailableBit != 0
	h.RCode = RCode(flags & rcodeMask)

	h.QuestionRecords = int(binary.BigEndian.Uint16(data[questionRecordsOffset:]))
	h.AnswerRecords = int(binary.BigEndian.Uint16(data[answerRecordsOffset:]))
	h.NameServerRecords = int(binary.BigEndian.Uint16(data[nameServerRecordsOffset:]))
	h.AddtitionalRecords = int(binary.BigEndian.Uint16(data[addtitionalRecordsOffset:]))

	return &h, headerBytes
}

func (h *Header) Put(buffer []byte) int {
	binary.BigEndian.PutUint16(buffer, uint16(h.ID))

	var flags uint16
	if h.Query {
		flags |= queryBit
	}
	flags |= uint16(h.Opcode) << opcodeOffset
	if h.AuthoritativeAnswer {
		flags |= authoritativeAnswerBit
	}
	if h.Truncation {
		flags |= truncationBit
	}
	if h.RecursionDesired {
		flags |= recursionDesiredBit
	}
	if h.RecursionAvailable {
		flags |= recursionAvailableBit
	}
	flags |= uint16(h.RCode)
	binary.BigEndian.PutUint16(buffer[flagsOffset:], flags)

	binary.BigEndian.PutUint16(buffer[questionRecordsOffset:], uint16(h.QuestionRecords))
	binary.BigEndian.PutUint16(buffer[answerRecordsOffset:], uint16(h.AnswerRecords))
	binary.BigEndian.PutUint16(buffer[nameServerRecordsOffset:], uint16(h.NameServerRecords))
	binary.BigEndian.PutUint16(buffer[addtitionalRecordsOffset:], uint16(h.AddtitionalRecords))

	return headerBytes
}

////////////////////////////////////////////////////////////////////////////////

type Name []string

func ParseName(data []byte) (Name, int) {
	offset := 0
	name := make([]string, 0)
	for bytes := int(data[offset]); bytes != 0; {
		name = append(name, string(data[offset+1:offset+bytes+1]))
		offset += bytes + 1
	}

	return name, offset + 1
}

func (n Name) Put(buffer []byte) int {
	offset := 0
	for _, label := range n {
		buffer[offset] = byte(len(label))
		copy(buffer[offset+1:], []byte(label))
		offset += 1 + len(label)
	}

	buffer[offset] = 0
	return offset + 1
}

////////////////////////////////////////////////////////////////////////////////

type QType int

const (
	AXFR QType = iota + 252
	MAILB
	MAILA
	ALL
)

type Type QType

const (
	A Type = iota + 1
	NS
	MD
	MF
	CNAME
	SOA
	MB
	MG
	MR
	NULL
	WKS
	PTR
	HINFO
	MINFO
	MX
	TXT
)

type QClass int

const (
	ANY QClass = 255
)

type Class QClass

const (
	IN Class = iota + 1
	CS
	CH
	HS
)

type Record struct {
	Name       Name
	Type       Type
	Class      Class
	TTLSeconds int
	Data       []byte
}

func ParseRecord(data []byte) (*Record, int) {
	var r Record

	var offset int
	r.Name, offset = ParseName(data)

	r.Type = Type(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	r.Class = Class(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	r.TTLSeconds = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	dataLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	r.Data = data[offset : offset+int(dataLen)]
	offset += int(dataLen)

	return &r, offset
}

func (r *Record) Put(buffer []byte) int {
	offset := r.Name.Put(buffer)

	var u16_buffer [2]byte
	binary.BigEndian.PutUint16(u16_buffer[:], uint16(r.Type))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(r.Class))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(r.TTLSeconds))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(len(r.Data)))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	copy(buffer[offset:], []byte(r.Data))
	offset += len(r.Data)

	return offset
}

////////////////////////////////////////////////////////////////////////////////

type Question struct {
	Name   Name
	QType  QType
	QClass QClass
}

func ParseQuestion(data []byte) (*Question, int) {
	var q Question

	var offset int
	q.Name, offset = ParseName(data)

	q.QType = QType(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	q.QClass = QClass(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	return &q, offset
}

func (q *Question) Put(buffer []byte) int {
	offset := q.Name.Put(buffer)

	var u16_buffer [2]byte
	binary.BigEndian.PutUint16(u16_buffer[:], uint16(q.QType))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(q.QClass))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	return offset
}

//////////////////////////////////////////////////////////////////////

type Message struct {
	Header     *Header
	Question   []Question
	Answer     []Record
	Authority  []Record
	Additional []Record
}

func ParseMessage(data []byte) (*Message, int) {
	var m Message

	var offset int
	m.Header, offset = ParseHeader(data)

	m.Question = make([]Question, m.Header.QuestionRecords)
	for i := 0; i < m.Header.QuestionRecords; i++ {
		question, bytes := ParseQuestion(data[offset:])
		m.Question = append(m.Question, *question)
		offset += bytes
	}

	m.Answer = make([]Record, m.Header.AnswerRecords)
	for i := 0; i < m.Header.AnswerRecords; i++ {
		answer, bytes := ParseRecord(data[offset:])
		m.Answer = append(m.Answer, *answer)
		offset += bytes
	}

	m.Authority = make([]Record, m.Header.NameServerRecords)
	for i := 0; i < m.Header.NameServerRecords; i++ {
		answer, bytes := ParseRecord(data[offset:])
		m.Authority = append(m.Authority, *answer)
		offset += bytes
	}

	m.Additional = make([]Record, m.Header.AddtitionalRecords)
	for i := 0; i < m.Header.AddtitionalRecords; i++ {
		answer, bytes := ParseRecord(data[offset:])
		m.Additional = append(m.Additional, *answer)
		offset += bytes
	}

	return &m, offset
}

func (m *Message) Put(buffer []byte) int {
	offset := m.Header.Put(buffer)

	for _, q := range m.Question {
		offset += q.Put(buffer[offset:])
	}
	for _, a := range m.Answer {
		offset += a.Put(buffer[offset:])
	}
	for _, a := range m.Authority {
		offset += a.Put(buffer[offset:])
	}
	for _, a := range m.Additional {
		offset += a.Put(buffer[offset:])
	}

	return offset
}
