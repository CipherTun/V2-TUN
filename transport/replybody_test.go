package transport

import (
	"io"
	"strings"
	"testing"
)

func TestIsChunked(t *testing.T) {
	yes := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	yes2 := "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, Chunked\r\n\r\n"
	no := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	if !isChunked(yes) || !isChunked(yes2) || isChunked(no) {
		t.Fatal("isChunked gave a wrong answer")
	}
}

// The data after the body must be left untouched: it is the SSH banner.
func TestSkipChunkedStopsAtEnd(t *testing.T) {
	body := "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
	r := strings.NewReader(body + "SSH-2.0-test\r\n")
	if err := skipChunked(r, 1<<16); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "SSH-2.0-test\r\n" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestSkipChunkedEmptyBody(t *testing.T) {
	r := strings.NewReader("0\r\n\r\nSSH-2.0-x\r\n")
	if err := skipChunked(r, 1<<16); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "SSH-2.0-x\r\n" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestSkipChunkedErrors(t *testing.T) {
	cases := map[string]string{
		"bad size":    "zz\r\n",
		"plus sign":   "+5\r\nhello\r\n0\r\n\r\n",
		"minus sign":  "-0\r\n\r\n",
		"empty size":  "\r\n",
		"too large":   "ffff\r\n" + strings.Repeat("a", 0xffff) + "\r\n0\r\n\r\n",
		"no crlf":     "3\r\nabcXY",
		"cut off":     "10\r\nabc",
		"no trailer":  "0\r\n",
		"empty input": "",
	}
	for name, in := range cases {
		limit := int64(1 << 16)
		if name == "too large" {
			limit = 100
		}
		if err := skipChunked(strings.NewReader(in), limit); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A huge chunk size after a small one must hit the cap, not wrap the running
// total around int64 and slip past it.
func TestSkipChunkedSizeOverflow(t *testing.T) {
	in := "1\r\na\r\n7fffffffffffffff\r\n"
	err := skipChunked(strings.NewReader(in), 1<<16)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want the size cap error", err)
	}
}
