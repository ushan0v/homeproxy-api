package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var benchSink int

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  homeproxy-api [-db /var/run/homeproxy/cache.db] [-bench N] <domain-or-ip>")
	fmt.Fprintln(os.Stderr, "  homeproxy-api -listen 127.0.0.1:7860 [-db /var/run/homeproxy/cache.db] [-config /var/run/homeproxy/sing-box-c.json] [-allow-origin '*'] [-mode default|eco]")
	fmt.Fprintln(os.Stderr, "  homeproxy-api -port 7860 [-db /var/run/homeproxy/cache.db] [-config /var/run/homeproxy/sing-box-c.json] [-allow-origin '*'] [-mode default|eco]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Notes:")
	fmt.Fprintln(os.Stderr, "  - Reads sing-box remote rule-sets directly from homeproxy cache.db (bbolt), no temp .srs files.")
	fmt.Fprintln(os.Stderr, "  - Prints which cached rule-sets match the input domain/IP.")
	fmt.Fprintln(os.Stderr, "  - Server mode defaults to in-memory cache; use -mode eco (or -eco) for cold-run per request.")
	fmt.Fprintln(os.Stderr, "  - HTTP endpoints: GET /match, POST /check, GET /stats, GET /healthz.")
}

func shortTag(tag string) string {
	// homeproxy generates tags as: cfg-<uci_section>-rule
	if strings.HasPrefix(tag, "cfg-") && strings.HasSuffix(tag, "-rule") && len(tag) > len("cfg--rule") {
		return tag[len("cfg-") : len(tag)-len("-rule")]
	}
	return tag
}

func extractSRSBytes(v []byte) ([]byte, error) {
	// homeproxy/sing-box stores rule-set payloads in cache.db values like:
	//   0x01 <uvarint payload_len> <payload bytes...> <trailing...>
	// where payload starts with "SRS" magic.
	if len(v) < 8 {
		return nil, E.New("value too short")
	}
	payloadLen, n := binary.Uvarint(v[1:])
	if n <= 0 {
		return nil, E.New("invalid uvarint length")
	}
	start := 1 + n
	end := start + int(payloadLen)
	if start < 0 || end < 0 || start > len(v) || end > len(v) {
		return nil, E.New("payload out of range")
	}
	payload := v[start:end]
	if len(payload) < 4 || !bytes.Equal(payload[:3], []byte("SRS")) {
		return nil, E.New("missing SRS magic")
	}
	return payload, nil
}

func buildMetadata(input string) adapter.InboundContext {
	var meta adapter.InboundContext
	if ip := M.ParseAddr(input); ip.IsValid() {
		meta.Destination = M.SocksaddrFrom(ip, 0)
	} else {
		meta.Domain = input
	}
	return meta
}

func compileRuleSet(ctx context.Context, ruleSetCompatBytes []byte) ([]adapter.HeadlessRule, error) {
	ruleSetCompat, err := srs.Read(bytes.NewReader(ruleSetCompatBytes), false)
	if err != nil {
		return nil, err
	}
	plainRuleSet, err := ruleSetCompat.Upgrade()
	if err != nil {
		return nil, err
	}
	compiled := make([]adapter.HeadlessRule, 0, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		currentRule, err := rule.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rules.[", i, "]")
		}
		compiled = append(compiled, currentRule)
	}
	return compiled, nil
}

func matchAny(rules []adapter.HeadlessRule, meta *adapter.InboundContext) bool {
	for _, r := range rules {
		if r.Match(meta) {
			return true
		}
	}
	return false
}

func main() {
	var (
		dbPath      string
		benchN      int
		listen      string
		port        int
		configPath  string
		allowOrigin string
		mode        string
		eco         bool
	)
	flag.StringVar(&dbPath, "db", "/var/run/homeproxy/cache.db", "path to homeproxy/sing-box cache.db")
	flag.IntVar(&benchN, "bench", 0, "benchmark match stage N times per ruleset (after parsing); 0 disables")
	flag.StringVar(&listen, "listen", "", "run as HTTP server on this address, e.g. 127.0.0.1:7860")
	flag.IntVar(&port, "port", 0, "run as HTTP server on 0.0.0.0:<port> (shortcut for -listen)")
	flag.StringVar(&configPath, "config", "", "optional path to sing-box config json (for tags/urls mapping)")
	flag.StringVar(&allowOrigin, "allow-origin", "*", "CORS Access-Control-Allow-Origin value for HTTP mode")
	flag.StringVar(&mode, "mode", "default", "server mode: default (cached) or eco (cold-run per request)")
	flag.BoolVar(&eco, "eco", false, "alias of -mode eco")
	flag.Usage = usage
	flag.Parse()

	if eco {
		mode = "eco"
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "default"
	}
	if mode != "default" && mode != "eco" {
		fmt.Fprintln(os.Stderr, "invalid -mode, expected default or eco")
		os.Exit(2)
	}
	if listen == "" && port > 0 {
		listen = fmt.Sprintf("0.0.0.0:%d", port)
	}

	if listen != "" {
		if configPath == "" {
			configPath = defaultConfigPath()
		}
		svc := &matchService{
			dbPath:      dbPath,
			configPath:  configPath,
			allowOrigin: allowOrigin,
			mode:        mode,
			ecoMode:     mode == "eco",
		}
		if err := svc.serve(listen); err != nil {
			fmt.Fprintln(os.Stderr, "server:", err)
			os.Exit(1)
		}
		return
	}

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	input := flag.Arg(0)

	meta := buildMetadata(input)

	// cache.db is usually locked by the running sing-box process (bbolt uses flock),
	// so we mmap+parse it without taking any locks.
	db, err := openBoltNoLock(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.Background()

	var (
		totalStart   = time.Now()
		parseTotal   time.Duration
		matchTotal   time.Duration
		benchTotal   time.Duration
		ruleSetCount int
		matched      []string
		errorsCount  int
	)

	err = db.forEachRuleSetKV(func(k string, v []byte) error {
		ruleSetCount++

		parseStart := time.Now()
		srsBytes, err := extractSRSBytes(v)
		if err != nil {
			errorsCount++
			return nil
		}
		compiled, err := compileRuleSet(ctx, srsBytes)
		if err != nil {
			errorsCount++
			return nil
		}
		parseTotal += time.Since(parseStart)

		matchStart := time.Now()
		ok := matchAny(compiled, &meta)
		matchTotal += time.Since(matchStart)

		if benchN > 0 {
			benchStart := time.Now()
			hits := 0
			for i := 0; i < benchN; i++ {
				if matchAny(compiled, &meta) {
					hits++
				}
			}
			benchSink += hits
			benchTotal += time.Since(benchStart)
		}

		if ok {
			matched = append(matched, k)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "read db:", err)
		os.Exit(1)
	}

	totalDur := time.Since(totalStart)

	fmt.Printf("db=%s\n", dbPath)
	if meta.Domain != "" {
		fmt.Printf("input(domain)=%s\n", meta.Domain)
	} else {
		fmt.Printf("input(ip)=%s\n", input)
	}
	fmt.Printf("rulesets_scanned=%d errors=%d\n", ruleSetCount, errorsCount)
	fmt.Printf("time_total=%s time_parse=%s time_match=%s\n", totalDur, parseTotal, matchTotal)

	if len(matched) == 0 {
		fmt.Println("matched=0")
		return
	}

	fmt.Printf("matched=%d\n", len(matched))
	for _, tag := range matched {
		fmt.Printf("- %s (%s)\n", shortTag(tag), tag)
	}

	if benchN > 0 {
		avgScan := benchTotal / time.Duration(max(benchN, 1))
		avgRuleset := benchTotal / time.Duration(max(benchN*max(ruleSetCount, 1), 1))
		fmt.Printf("bench: iters=%d time_total=%s avg_per_scan=%s avg_per_ruleset=%s\n", benchN, benchTotal, avgScan, avgRuleset)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
