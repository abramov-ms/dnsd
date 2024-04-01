package dns

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

var ErrBadDbFormat = fmt.Errorf("bad database format")
var ErrNotImplemented = fmt.Errorf("not implemented")

type Db map[string]*Record

func ImportDb(path string) (Db, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	db := make(Db)
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if semicolon := strings.Index(line, ";"); semicolon != -1 {
			line = line[:semicolon]
		}
		if len(line) == 0 {
			continue
		}

		words := bufio.NewScanner(strings.NewReader(lines.Text()))
		words.Split(bufio.ScanWords)
		rname, err := consumeWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected domain name", err)
		}
		rclass, err := consumeWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected record class", err)
		}
		rtype, err := consumeWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected record type", err)
		}
		rdata, err := consumeWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected record data", err)
		}

		if rclass != "IN" || rtype != "A" {
			return nil, ErrNotImplemented
		}
		record, err := newInAddrRecord(rname, rdata)
		if err != nil {
			return nil, err
		}

		db[rname] = record
	}

	if err := lines.Err(); err != nil {
		return nil, err
	}

	return db, nil
}

func newInAddrRecord(domain string, ip string) (*Record, error) {
	var r Record
	r.Class = IN
	r.Type = A
	r.Name = strings.Split(domain, ".")
	r.TTLSeconds = 600

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	bytes := addr.As4()
	r.Data = bytes[:]

	return &r, nil
}

func consumeWord(s *bufio.Scanner) (string, error) {
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return "", err
		} else {
			return "", ErrBadDbFormat
		}
	}

	return s.Text(), nil
}
