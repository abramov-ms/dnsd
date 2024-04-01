package dns

import (
	"encoding/binary"
	"fmt"
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
	Response            bool
	OpCode              OpCode
	AuthoritativeAnswer bool
	Truncation          bool
	RecursionDesired    bool
	RecursionAvailable  bool
	RCode               RCode
	QuestionRecords     int
	AnswerRecords       int
	NameServerRecords   int
	AdditionalRecords   int
}

const (
	headerBytes = 12
	idOffset    = 0

	flagsOffset            = 2
	responseBit            = 1 << 15
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

var ErrBadRequestFormat = fmt.Errorf("bad DNS request format")

func ParseHeader(data []byte) (*Header, int, error) {
	if len(data) < headerBytes {
		return nil, 0, ErrBadRequestFormat
	}

	var h Header
	h.ID = int(binary.BigEndian.Uint16(data[idOffset:]))

	flags := binary.BigEndian.Uint16(data[flagsOffset:])
	h.Response = flags&responseBit != 0
	h.OpCode = OpCode((flags >> opcodeOffset) & opcodeMask)
	h.AuthoritativeAnswer = flags&authoritativeAnswerBit != 0
	h.Truncation = flags&truncationBit != 0
	h.RecursionDesired = flags&recursionDesiredBit != 0
	h.RecursionAvailable = flags&recursionAvailableBit != 0
	h.RCode = RCode(flags & rcodeMask)

	h.QuestionRecords = int(binary.BigEndian.Uint16(data[questionRecordsOffset:]))
	h.AnswerRecords = int(binary.BigEndian.Uint16(data[answerRecordsOffset:]))
	h.NameServerRecords = int(binary.BigEndian.Uint16(data[nameServerRecordsOffset:]))
	h.AdditionalRecords = int(binary.BigEndian.Uint16(data[addtitionalRecordsOffset:]))

	return &h, headerBytes, nil
}

func (h *Header) Put(buffer []byte) int {
	if len(buffer) < headerBytes {
		panic("too short buffer for DNS header")
	}

	binary.BigEndian.PutUint16(buffer, uint16(h.ID))

	var flags uint16
	if h.Response {
		flags |= responseBit
	}
	flags |= uint16(h.OpCode) << opcodeOffset
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
	binary.BigEndian.PutUint16(buffer[addtitionalRecordsOffset:], uint16(h.AdditionalRecords))

	return headerBytes
}

////////////////////////////////////////////////////////////////////////////////

type Name []string

func ParseName(data []byte) (Name, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrBadRequestFormat
	}

	offset := 0
	name := make([]string, 0)
	bytes := int(data[offset])
	for bytes != 0 {
		if len(data) < offset+bytes+1 {
			return nil, 0, ErrBadRequestFormat
		}

		name = append(name, string(data[offset+1:offset+bytes+1]))
		offset += bytes + 1
		bytes = int(data[offset])
	}

	return name, offset + 1, nil
}

func (n Name) Put(buffer []byte) int {
	offset := 0
	for _, label := range n {
		if len(buffer) < offset+1+len(label) {
			panic("too short buffer for domain name")
		}

		buffer[offset] = byte(len(label))
		copy(buffer[offset+1:], []byte(label))
		offset += 1 + len(label)
	}

	if len(buffer) < offset {
		panic("too short buffer for domain name")
	}

	buffer[offset] = 0
	return offset + 1
}

////////////////////////////////////////////////////////////////////////////////

type Type int

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

type QType Type

const (
	AXFR QType = iota + 252
	MAILB
	MAILA
	ALL
)

type Class int

const (
	IN Class = iota + 1
	CS
	CH
	HS
)

type QClass Class

const (
	ANY QClass = 255
)

type Record struct {
	Name       Name
	Type       Type
	Class      Class
	TTLSeconds int64
	Data       []byte
}

func ParseRecord(data []byte) (*Record, int, error) {
	var r Record

	var offset int
	var err error
	r.Name, offset, err = ParseName(data)
	if err != nil {
		return nil, 0, err
	}

	if len(data) < offset+2+2+4+2 {
		return nil, 0, ErrBadRequestFormat
	}

	r.Type = Type(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	r.Class = Class(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	r.TTLSeconds = int64(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	dataLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if len(data) < offset+dataLen {
		return nil, 0, ErrBadRequestFormat
	}

	r.Data = data[offset : offset+dataLen]
	offset += dataLen

	return &r, offset, nil
}

func (r *Record) Put(buffer []byte) int {
	offset := r.Name.Put(buffer)

	if len(buffer) < offset+2+2+4+2+len(r.Data) {
		panic("too short buffer for DNS record")
	}

	var u16_buffer [2]byte
	binary.BigEndian.PutUint16(u16_buffer[:], uint16(r.Type))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(r.Class))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	var u32_buffer [4]byte
	binary.BigEndian.PutUint32(u32_buffer[:], uint32(r.TTLSeconds))
	copy(buffer[offset:], u32_buffer[:])
	offset += 4

	binary.BigEndian.PutUint16(u16_buffer[:], uint16(len(r.Data)))
	copy(buffer[offset:], u16_buffer[:])
	offset += 2

	copy(buffer[offset:], r.Data)
	offset += len(r.Data)

	return offset
}

////////////////////////////////////////////////////////////////////////////////

type Question struct {
	Name   Name
	QType  QType
	QClass QClass
}

func ParseQuestion(data []byte) (*Question, int, error) {
	var q Question

	var offset int
	var err error
	q.Name, offset, err = ParseName(data)
	if err != nil {
		return nil, 0, err
	}

	if len(data) < offset+2+2 {
		return nil, 0, ErrBadRequestFormat
	}

	q.QType = QType(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	q.QClass = QClass(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	return &q, offset, nil
}

func (q *Question) Put(buffer []byte) int {
	offset := q.Name.Put(buffer)

	if len(buffer) < offset+2+2 {
		panic("too short buffer for DNS question")
	}

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
	Header      *Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additional  []Record
}

func ParseMessage(data []byte) (*Message, int, error) {
	var m Message

	var offset int
	var err error
	m.Header, offset, err = ParseHeader(data)
	if err != nil {
		return nil, 0, err
	}

	m.Questions = make([]Question, m.Header.QuestionRecords)
	for i := 0; i < m.Header.QuestionRecords; i++ {
		question, bytes, err := ParseQuestion(data[offset:])
		if err != nil {
			return nil, 0, err
		}

		m.Questions[i] = *question
		offset += bytes
	}

	m.Answers = make([]Record, m.Header.AnswerRecords)
	for i := 0; i < m.Header.AnswerRecords; i++ {
		answer, bytes, err := ParseRecord(data[offset:])
		if err != nil {
			return nil, 0, err
		}

		m.Answers[i] = *answer
		offset += bytes
	}

	m.Authorities = make([]Record, m.Header.NameServerRecords)
	for i := 0; i < m.Header.NameServerRecords; i++ {
		answer, bytes, err := ParseRecord(data[offset:])
		if err != nil {
			return nil, 0, err
		}

		m.Authorities[i] = *answer
		offset += bytes
	}

	m.Additional = make([]Record, m.Header.AdditionalRecords)
	for i := 0; i < m.Header.AdditionalRecords; i++ {
		answer, bytes, err := ParseRecord(data[offset:])
		if err != nil {
			return nil, 0, err
		}

		m.Additional[i] = *answer
		offset += bytes
	}

	return &m, offset, nil
}

func (m *Message) Put(buffer []byte) int {
	offset := m.Header.Put(buffer)

	for _, q := range m.Questions {
		offset += q.Put(buffer[offset:])
	}
	for _, a := range m.Answers {
		offset += a.Put(buffer[offset:])
	}
	for _, a := range m.Authorities {
		offset += a.Put(buffer[offset:])
	}
	for _, a := range m.Additional {
		offset += a.Put(buffer[offset:])
	}

	return offset
}
