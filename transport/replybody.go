package transport

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// isChunked reports whether a reply's header block announces a chunked body
// ("Transfer-Encoding: chunked", possibly among other codings).
func isChunked(head string) bool {
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "transfer-encoding") {
			continue
		}
		for _, enc := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(enc), "chunked") {
				return true
			}
		}
	}
	return false
}

// readLine reads one line byte by byte, so nothing past it is consumed (the
// tunnel stream may follow right after the last chunk). It returns the line
// without the line ending and fails when the line is longer than max bytes.
func readLine(r io.Reader, max int) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for len(buf) <= max {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return strings.TrimSuffix(string(buf), "\r"), nil
		}
		buf = append(buf, b[0])
	}
	return "", errors.New("line too long")
}

// parseChunkSize parses a chunk-size line (extensions already removed). Only
// hex digits are accepted, so a sign ("+5", "-0") is refused, as is an empty
// value or one too long for an int64.
func parseChunkSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 16 || strings.Trim(s, "0123456789abcdefABCDEF") != "" {
		return 0, fmt.Errorf("bad chunk size %q", s)
	}
	size, err := strconv.ParseInt(s, 16, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("bad chunk size %q", s)
	}
	return size, nil
}

// skipChunked reads and drops a chunked reply body, including the trailer
// after the last chunk, and stops exactly at its end. limit caps the total
// size of the chunk data; a body that is larger is more likely a real page
// than a made-up reply in front of a tunnel, so it is refused with an error
// instead of being half-read.
func skipChunked(r io.Reader, limit int64) error {
	var total int64
	for {
		line, err := readLine(r, 1024)
		if err != nil {
			return fmt.Errorf("chunk size: %w", err)
		}
		if i := strings.IndexByte(line, ';'); i >= 0 { // chunk extensions
			line = line[:i]
		}
		size, err := parseChunkSize(line)
		if err != nil {
			return err
		}
		if size == 0 {
			// trailer: header lines up to an empty line
			for n := 0; ; n++ {
				l, err := readLine(r, 8192)
				if err != nil {
					return fmt.Errorf("chunk trailer: %w", err)
				}
				if l == "" {
					return nil
				}
				if n > 100 {
					return errors.New("chunk trailer too long")
				}
			}
		}
		// Compare without adding: total+size could overflow int64.
		if size > limit-total {
			return fmt.Errorf("chunked body is larger than %d bytes", limit)
		}
		total += size
		if _, err := io.CopyN(io.Discard, r, size); err != nil {
			return fmt.Errorf("chunk data: %w", err)
		}
		end, err := readLine(r, 16) // the CRLF after the data
		if err != nil || end != "" {
			return errors.New("chunk is not followed by a line ending")
		}
	}
}
