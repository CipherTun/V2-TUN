package mobile

import (
	"context"

	v2tun "io.surprise.vpn"
	"io.surprise.vpn/internal/logx"
)

// Logging for the app's Logs tab. Everything stays in memory: the library
// keeps the most recent entries and pushes new ones to a LogSink; nothing is
// written to a file.

// LogSink is implemented in Kotlin. OnLog gets one entry as JSON:
// {"seq":12,"t":1731100000000,"level":"warn","c":"failover","msg":"...","attrs":{"k":"v"}}
// where "t" is Unix milliseconds and level is debug, info, warn or error.
// It is called on a background thread.
type LogSink interface{ OnLog(entryJSON string) }

// SetLogSink starts (or, with null, stops) the live feed of log entries.
func SetLogSink(s LogSink) {
	if s == nil {
		logx.SetSink(nil)
		return
	}
	logx.SetSink(s.OnLog)
}

// SetLogLevel sets the minimum level recorded: debug, info (default), warn or
// error. It can change while the tunnel runs.
func SetLogLevel(level string) { logx.SetLevel(logx.ParseLevel(level)) }

// RecentLogs returns up to max of the newest entries as a JSON array, oldest
// first (max <= 0: everything kept). Use it to fill the Logs tab when it opens.
func RecentLogs(max int) string { return logx.RecentJSON(max) }

// ClearLogs forgets the entries kept in memory.
func ClearLogs() { logx.Clear() }

// DroppedLogs counts entries missing from the live feed because the app's sink
// fell behind; they are still returned by RecentLogs while they are kept.
func DroppedLogs() int64 { return logx.Dropped() }

// AppLog lets the app add its own line (for example "VPN permission granted")
// to the same stream, as component "app".
func AppLog(level, message string) {
	logx.L("app").Log(context.Background(), logx.ParseLevel(level), message)
}

// FaultListener is implemented in Kotlin and receives actionable errors (for
// example a dial that failed on every outbound), at most about one a second,
// for a toast or a banner. The same errors also appear in the log.
type FaultListener interface{ OnFault(message string) }

// SetFaultListener registers l, or removes it with null.
func SetFaultListener(l FaultListener) {
	if l == nil {
		v2tun.SetFaultHandler(nil)
		return
	}
	v2tun.SetFaultHandler(l.OnFault)
}
