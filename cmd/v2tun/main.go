// Command v2tun is a small command line for the v2-tun library: run a local
// SOCKS5 proxy through a config, convert share links, check configs and
// payloads, ping, speed test and scan bug hosts. It runs in Termux, so a
// config can be tried on the phone without building the app.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	v2tun "io.surprise.vpn"
	"io.surprise.vpn/socks"
)

const usage = `v2tun - command line for the v2-tun library

usage: v2tun <command> [flags]

  run       -c config.json [-l 127.0.0.1:10808] [-user U -pass P]
                                                  local SOCKS5 proxy (CONNECT and UDP ASSOCIATE)
  link      <share link>                          print the JSON config of a share link
  validate  -c config.json                        check a config without connecting
  payload   -c config.json                        show what the payload would send
  ping      -c config.json [-url URL]             time to a first response through the tunnel
  speed     -c config.json [-url URL] [-t 10]     download speed through the tunnel
  scan      -c config.json -hosts file [flags]    find which hosts a network lets through

A config file of - is read from standard input.

scan flags: -field payload.host|tls.sni|ws.host|payload.proxy|server  (default payload.host)
            -target URL or host:port   (default http://www.gstatic.com/generate_204)
            -j 3   probes at a time    -t 15   seconds per probe
The hosts file has one value per line; blank lines and lines starting with # are skipped.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd := os.Args[1]; cmd {
	case "run":
		err = cmdRun(os.Args[2:])
	case "link":
		err = cmdLink(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "payload":
		err = cmdPayload(os.Args[2:])
	case "ping":
		err = cmdPing(os.Args[2:])
	case "speed":
		err = cmdSpeed(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*v2tun.Config, error) {
	if path == "" {
		return nil, fmt.Errorf("missing -c config.json")
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var cfg v2tun.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	listen := fs.String("l", "127.0.0.1:10808", "local SOCKS5 listen address")
	user := fs.String("user", "", "SOCKS5 username (enables authentication)")
	pass := fs.String("pass", "", "SOCKS5 password")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	cl, err := v2tun.New(cfg)
	if err != nil {
		return err
	}
	defer cl.Close()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "SOCKS5 proxy on %s (Ctrl+C to stop)\n", ln.Addr())
	err = socks.ServeOpts(ctx, ln, cl, socks.Options{Username: *user, Password: *pass, UDP: cl})
	up, down := v2tun.Traffic()
	fmt.Fprintf(os.Stderr, "sent %d bytes, received %d bytes\n", up, down)
	return err
}

func cmdLink(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: v2tun link <share link>")
	}
	cfg, name, err := v2tun.ParseLink(args[0])
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(struct {
		*v2tun.Config
		Name string `json:"name"`
	}{cfg, name}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	cl, err := v2tun.New(cfg)
	if err != nil {
		return err
	}
	cl.Close()
	fmt.Println("config is valid")
	return nil
}

func cmdPayload(args []string) error {
	fs := flag.NewFlagSet("payload", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	out, err := v2tun.PreviewPayload(cfg)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

func cmdPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	url := fs.String("url", "", "URL to fetch (default: gstatic generate_204)")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	cl, err := v2tun.New(cfg)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := cl.Ping(ctx, *url)
	if err != nil {
		return err
	}
	fmt.Printf("%d ms\n", d.Milliseconds())
	return nil
}

func cmdSpeed(args []string) error {
	fs := flag.NewFlagSet("speed", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	url := fs.String("url", "", "URL to download (default: Cloudflare speed test)")
	secs := fs.Int("t", 10, "seconds to download")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	cl, err := v2tun.New(cfg)
	if err != nil {
		return err
	}
	defer cl.Close()
	n, bps, err := cl.SpeedTest(context.Background(), *url, time.Duration(*secs)*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("%.1f Mbit/s (%d bytes)\n", bps/1e6, n)
	return nil
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	conf := fs.String("c", "", "config file (JSON)")
	field := fs.String("field", "payload.host", "field to replace")
	hosts := fs.String("hosts", "", "file with one value per line")
	target := fs.String("target", "http://www.gstatic.com/generate_204", "URL or host:port to test")
	par := fs.Int("j", 3, "probes at a time")
	secs := fs.Int("t", 15, "seconds per probe")
	fs.Parse(args)
	cfg, err := loadConfig(*conf)
	if err != nil {
		return err
	}
	if *hosts == "" {
		return fmt.Errorf("missing -hosts file")
	}
	f, err := os.Open(*hosts)
	if err != nil {
		return err
	}
	defer f.Close()
	var values []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			values = append(values, l)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(values) == 0 {
		return fmt.Errorf("%s has no values", *hosts)
	}
	fmt.Fprintf(os.Stderr, "scanning %d values of %s ...\n", len(values), *field)
	res := v2tun.Scan(context.Background(), cfg, *field, values, *target, *par, time.Duration(*secs)*time.Second)
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].OK != res[j].OK {
			return res[i].OK
		}
		return res[i].Millis < res[j].Millis
	})
	working := 0
	for _, r := range res {
		if r.OK {
			working++
			fmt.Printf("OK    %5d ms  %s\n", r.Millis, r.Value)
		} else {
			fmt.Printf("FAIL  %-8s  %s  (%s)\n", "", r.Value, r.Error)
		}
	}
	fmt.Fprintf(os.Stderr, "%d of %d work\n", working, len(res))
	return nil
}
