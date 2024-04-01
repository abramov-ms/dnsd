package dns

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

var ErrBadDbFormat = fmt.Errorf("Bad database format")
var ErrNotImplemented = fmt.Errorf("Not implemented")

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
		if len(line) == 0 || strings.HasPrefix(line, ";") {
			continue
		}

		words := bufio.NewScanner(strings.NewReader(lines.Text()))
		words.Split(bufio.ScanWords)

		domain, err := nextWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected domain name", err)
		}

		class, err := nextWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected record class", err)
		}

		rtype, err := nextWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected record type", err)

		}

		ip, err := nextWord(words)
		if err != nil {
			return nil, fmt.Errorf("%w: expected IP address", err)
		}

		if class != "IN" || rtype != "A" {
			return nil, ErrNotImplemented
		}

		r, err := newINARecord(domain, ip)
		if err != nil {
			return nil, err
		}

		db[domain] = r
	}

	if err := lines.Err(); err != nil {
		return nil, err
	}

	return db, nil

}

func newINARecord(domain string, ip string) (*Record, error) {
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

func nextWord(s *bufio.Scanner) (string, error) {
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return "", err
		} else {
			return "", ErrBadDbFormat
		}
	}

	word := s.Text()
	if strings.HasPrefix(word, ";") {
		return "", ErrBadDbFormat
	}

	return word, nil
}
