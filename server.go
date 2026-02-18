package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	routeRule "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"go4.org/netipx"
)

type configOutbound struct {
	Type string `json:"type,omitempty"`
	Tag  string `json:"tag,omitempty"`
}

type runtimeConfig struct {
	Outbounds []configOutbound    `json:"outbounds,omitempty"`
	Route     option.RouteOptions `json:"route,omitempty"`
}

type compiledRuleSet struct {
	Tag   string
	Rules []adapter.HeadlessRule
}

type compiledRouteRule struct {
	Index int
	Rule  adapter.Rule
}

type localFileStamp struct {
	Path    string
	Size    int64
	ModTime time.Time
}

type matchState struct {
	LoadedAt time.Time

	DBPath    string
	DBSize    int64
	DBModTime time.Time

	ConfigPath     string
	ConfigSize     int64
	ConfigModTime  time.Time
	HomeproxyPath  string
	HomeproxySize  int64
	HomeproxyMTime time.Time
	LocalFiles     []localFileStamp

	RouteFinal        string
	DefaultTag        string
	OutboundType      map[string]string
	OutboundName      map[string]string
	RouteOutboundName map[string]string

	RuleSetInfo map[string]option.RuleSet
	RuleSets    []compiledRuleSet
	RuleSetMap  map[string]adapter.RuleSet
	RouteRules  []compiledRouteRule
	RuleNames   map[int]string
}

type matchService struct {
	dbPath      string
	configPath  string
	accessToken string
	mode        string
	ecoMode     bool

	reloadMu sync.Mutex
	state    atomic.Pointer[matchState]
}

func defaultConfigPath() string {
	paths := []string{
		"/var/run/homeproxy/sing-box-c.json",
		"/var/run/homeproxy/sing-box-s.json",
	}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func loadConfig(path string) (*runtimeConfig, os.FileInfo, []byte, error) {
	if path == "" {
		return nil, nil, nil, errors.New("empty config path")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if st.IsDir() {
		candidates := []string{
			filepath.Join(path, "sing-box-c.json"),
			filepath.Join(path, "sing-box-s.json"),
		}
		found := ""
		for _, c := range candidates {
			if cst, cErr := os.Stat(c); cErr == nil && cst.Mode().IsRegular() {
				found = c
				st = cst
				break
			}
		}
		if found == "" {
			return nil, nil, nil, fmt.Errorf("no sing-box-*.json in %s", path)
		}
		path = found
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var cfg runtimeConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, nil, nil, err
	}
	return &cfg, st, content, nil
}

func collectUsedRuleSetTags(routeRules []option.Rule) map[string]struct{} {
	if len(routeRules) == 0 {
		return nil
	}
	used := make(map[string]struct{})
	var walk func(r option.Rule)
	walk = func(r option.Rule) {
		switch strings.ToLower(r.Type) {
		case "logical":
			for _, child := range r.LogicalOptions.Rules {
				walk(child)
			}
		default:
			for _, tag := range r.DefaultOptions.RuleSet {
				tag = strings.TrimSpace(tag)
				if tag == "" {
					continue
				}
				used[tag] = struct{}{}
			}
		}
	}
	for _, rr := range routeRules {
		walk(rr)
	}
	if len(used) == 0 {
		return nil
	}
	return used
}

func filterRuleSetsByUsage(ruleSets []option.RuleSet, usedTags map[string]struct{}) []option.RuleSet {
	if len(ruleSets) == 0 || len(usedTags) == 0 {
		return nil
	}
	filtered := make([]option.RuleSet, 0, len(ruleSets))
	for _, rs := range ruleSets {
		if rs.Tag == "" {
			continue
		}
		if _, ok := usedTags[rs.Tag]; !ok {
			continue
		}
		filtered = append(filtered, rs)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func wantRemoteRuleSetTags(ruleSets []option.RuleSet) map[string]struct{} {
	if len(ruleSets) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(ruleSets))
	for _, rs := range ruleSets {
		if rs.Tag == "" || rs.Type != "remote" {
			continue
		}
		want[rs.Tag] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}
	return want
}

func loadRemoteRuleSetValues(dbPath string, want map[string]struct{}) (map[string][]byte, os.FileInfo, error) {
	st, err := os.Stat(dbPath)
	if err != nil {
		return nil, nil, err
	}
	db, err := openBoltNoLock(dbPath)
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	values := make(map[string][]byte, len(want))
	err = db.forEachRuleSetKV(func(k string, v []byte) error {
		if want != nil {
			if _, ok := want[k]; !ok {
				return nil
			}
		}
		values[k] = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return values, st, nil
}

func extractRuleNamesFromConfigJSON(content []byte) map[int]string {
	if len(content) == 0 {
		return nil
	}
	type rawRoute struct {
		Route struct {
			Rules []map[string]any `json:"rules,omitempty"`
		} `json:"route,omitempty"`
	}
	var raw rawRoute
	if err := json.Unmarshal(content, &raw); err != nil || len(raw.Route.Rules) == 0 {
		return nil
	}
	names := make(map[int]string, len(raw.Route.Rules))
	for i, ruleObj := range raw.Route.Rules {
		for _, key := range []string{"name", "rule_name", "label", "tag"} {
			value, ok := ruleObj[key]
			if !ok {
				continue
			}
			name := strings.TrimSpace(fmt.Sprintf("%v", value))
			if name == "" {
				continue
			}
			names[i] = name
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

type homeproxyMeta struct {
	OutboundNameByTag      map[string]string
	RouteOutboundNameByTag map[string]string
	RoutingRuleNames       []string
}

func stripInlineComment(line string) string {
	inQuote := false
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' {
			inQuote = !inQuote
		}
		if c == '#' && !inQuote {
			break
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

func trimUCIValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
			return raw[1 : len(raw)-1]
		}
		if raw[0] == '"' && raw[len(raw)-1] == '"' {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

func parseConfigLine(line string) (sectionType string, sectionName string, ok bool) {
	if !strings.HasPrefix(line, "config ") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "config "))
	if rest == "" {
		return "", "", false
	}
	idx := strings.IndexAny(rest, " \t")
	if idx < 0 {
		return "", "", false
	}
	sectionType = strings.TrimSpace(rest[:idx])
	sectionName = trimUCIValue(rest[idx+1:])
	if sectionType == "" || sectionName == "" {
		return "", "", false
	}
	return sectionType, sectionName, true
}

func parseOptionLine(line string) (key string, value string, ok bool) {
	if !strings.HasPrefix(line, "option ") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "option "))
	if rest == "" {
		return "", "", false
	}
	idx := strings.IndexAny(rest, " \t")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(rest[:idx])
	value = trimUCIValue(rest[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func routingNodeOutboundTagFromSection(section uciSection) string {
	node := strings.TrimSpace(section.Options["node"])
	if node == "" {
		return ""
	}
	switch strings.ToLower(node) {
	case "direct", "direct-out":
		return "direct-out"
	case "block", "block-out", "reject", "reject-out":
		return "block-out"
	case "urltest":
		return "cfg-" + section.Name + "-out"
	default:
		if strings.HasPrefix(node, "cfg-") && strings.HasSuffix(node, "-out") {
			return node
		}
		return "cfg-" + node + "-out"
	}
}

func loadHomeproxyMeta(path string) (*homeproxyMeta, error) {
	sections, err := parseUCISections(path)
	if err != nil {
		return nil, err
	}
	meta := &homeproxyMeta{
		OutboundNameByTag:      make(map[string]string),
		RouteOutboundNameByTag: make(map[string]string),
	}

	for _, section := range sections {
		label := strings.TrimSpace(section.Options["label"])
		switch section.Type {
		case "node":
			if label == "" {
				label = section.Name
			}
			if label != "" {
				meta.OutboundNameByTag["cfg-"+section.Name+"-out"] = label
			}
		case "routing_node":
			if strings.TrimSpace(section.Options["enabled"]) == "0" {
				continue
			}
			outboundTag := routingNodeOutboundTagFromSection(section)
			if outboundTag == "" {
				continue
			}
			routeName := label
			if routeName == "" {
				routeName = section.Name
			}
			if routeName == "" {
				continue
			}
			meta.RouteOutboundNameByTag[outboundTag] = routeName
		case "routing_rule":
			enabled := strings.TrimSpace(section.Options["enabled"])
			if enabled == "" || enabled == "1" {
				ruleName := label
				if ruleName == "" {
					ruleName = section.Name
				}
				if ruleName != "" {
					meta.RoutingRuleNames = append(meta.RoutingRuleNames, ruleName)
				}
			}
		}
	}
	return meta, nil
}

func normalizeOutboundName(tag string) string {
	tag = strings.TrimSpace(tag)
	if strings.HasPrefix(tag, "cfg-") && strings.HasSuffix(tag, "-out") && len(tag) > len("cfg--out") {
		return tag[len("cfg-") : len(tag)-len("-out")]
	}
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "direct", "direct-out":
		return "direct"
	case "block", "block-out", "reject", "reject-out":
		return "block"
	default:
		return tag
	}
}

func buildRuleNameIndex(routeRuleCount int, configRuleNames map[int]string, uciRuleNames []string) map[int]string {
	out := make(map[int]string)
	for idx, name := range configRuleNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out[idx] = name
	}
	if routeRuleCount == 0 || len(uciRuleNames) == 0 {
		return out
	}
	count := routeRuleCount
	if len(uciRuleNames) < count {
		count = len(uciRuleNames)
	}
	startRules := routeRuleCount - count
	startUCI := len(uciRuleNames) - count
	for i := 0; i < count; i++ {
		idx := startRules + i
		if _, exists := out[idx]; exists {
			continue
		}
		name := strings.TrimSpace(uciRuleNames[startUCI+i])
		if name == "" {
			continue
		}
		out[idx] = name
	}
	return out
}

func compileHeadlessRules(ctx context.Context, rules []option.HeadlessRule) ([]adapter.HeadlessRule, error) {
	compiled := make([]adapter.HeadlessRule, 0, len(rules))
	for i, ruleOptions := range rules {
		r, err := routeRule.NewHeadlessRule(ctx, ruleOptions)
		if err != nil {
			return nil, fmt.Errorf("parse rule_set.rules[%d]: %w", i, err)
		}
		compiled = append(compiled, r)
	}
	return compiled, nil
}

func inferRuleSetFormat(rs option.RuleSet) string {
	if rs.Format != "" {
		return rs.Format
	}
	switch rs.Type {
	case "remote":
		if strings.HasSuffix(strings.ToLower(rs.RemoteOptions.URL), ".srs") {
			return "binary"
		}
		return "source"
	case "local":
		if strings.HasSuffix(strings.ToLower(rs.LocalOptions.Path), ".srs") {
			return "binary"
		}
		return "source"
	default:
		return ""
	}
}

func resolveRuleSetPath(configPath string, rsPath string) string {
	if rsPath == "" {
		return rsPath
	}
	if filepath.IsAbs(rsPath) {
		return rsPath
	}
	if configPath == "" {
		return rsPath
	}
	baseDir := filepath.Dir(configPath)
	return filepath.Clean(filepath.Join(baseDir, rsPath))
}

func compileRuleSetFromOption(
	ctx context.Context,
	rs option.RuleSet,
	configPath string,
	remoteValues map[string][]byte,
) ([]adapter.HeadlessRule, *localFileStamp, error) {
	switch rs.Type {
	case "", "inline":
		compiled, err := compileHeadlessRules(ctx, rs.InlineOptions.Rules)
		if err != nil {
			return nil, nil, err
		}
		return compiled, nil, nil
	case "local":
		path := resolveRuleSetPath(configPath, rs.LocalOptions.Path)
		st, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		format := inferRuleSetFormat(rs)
		switch format {
		case "binary":
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, nil, err
			}
			compiled, err := compileRuleSet(ctx, content)
			if err != nil {
				return nil, nil, err
			}
			return compiled, &localFileStamp{Path: path, Size: st.Size(), ModTime: st.ModTime()}, nil
		case "source":
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, nil, err
			}
			compat, err := sjson.UnmarshalExtended[option.PlainRuleSetCompat](content)
			if err != nil {
				return nil, nil, err
			}
			plain, err := compat.Upgrade()
			if err != nil {
				return nil, nil, err
			}
			compiled, err := compileHeadlessRules(ctx, plain.Rules)
			if err != nil {
				return nil, nil, err
			}
			return compiled, &localFileStamp{Path: path, Size: st.Size(), ModTime: st.ModTime()}, nil
		default:
			return nil, nil, fmt.Errorf("unknown local rule-set format: %q", format)
		}
	case "remote":
		raw, ok := remoteValues[rs.Tag]
		if !ok {
			return nil, nil, fmt.Errorf("remote rule-set %q not found in cache.db", rs.Tag)
		}
		format := inferRuleSetFormat(rs)
		switch format {
		case "binary":
			srsBytes, err := extractSRSBytes(raw)
			if err != nil {
				return nil, nil, err
			}
			compiled, err := compileRuleSet(ctx, srsBytes)
			if err != nil {
				return nil, nil, err
			}
			return compiled, nil, nil
		case "source":
			compat, err := sjson.UnmarshalExtended[option.PlainRuleSetCompat](raw)
			if err != nil {
				return nil, nil, err
			}
			plain, err := compat.Upgrade()
			if err != nil {
				return nil, nil, err
			}
			compiled, err := compileHeadlessRules(ctx, plain.Rules)
			if err != nil {
				return nil, nil, err
			}
			return compiled, nil, nil
		default:
			return nil, nil, fmt.Errorf("unknown remote rule-set format: %q", format)
		}
	default:
		return nil, nil, fmt.Errorf("unknown rule-set type: %q", rs.Type)
	}
}

func (s *matchService) needsReload() (bool, os.FileInfo, os.FileInfo, error) {
	cfgSt, err := os.Stat(s.configPath)
	if err != nil {
		return false, nil, nil, err
	}
	dbSt, _ := os.Stat(s.dbPath)

	prev := s.state.Load()
	if prev == nil {
		return true, cfgSt, dbSt, nil
	}
	if cfgSt.Size() != prev.ConfigSize || !cfgSt.ModTime().Equal(prev.ConfigModTime) {
		return true, cfgSt, dbSt, nil
	}
	if dbSt != nil {
		if dbSt.Size() != prev.DBSize || !dbSt.ModTime().Equal(prev.DBModTime) {
			return true, cfgSt, dbSt, nil
		}
	} else if prev.DBSize != 0 {
		return true, cfgSt, dbSt, nil
	}
	for _, lf := range prev.LocalFiles {
		cur, statErr := os.Stat(lf.Path)
		if statErr != nil {
			return true, cfgSt, dbSt, nil
		}
		if cur.Size() != lf.Size || !cur.ModTime().Equal(lf.ModTime) {
			return true, cfgSt, dbSt, nil
		}
	}
	if prev.HomeproxyPath != "" {
		hpSt, hpErr := os.Stat(prev.HomeproxyPath)
		if hpErr != nil {
			return true, cfgSt, dbSt, nil
		}
		if hpSt.Size() != prev.HomeproxySize || !hpSt.ModTime().Equal(prev.HomeproxyMTime) {
			return true, cfgSt, dbSt, nil
		}
	}
	return false, cfgSt, dbSt, nil
}

func closeMatchState(state *matchState) {
	if state == nil {
		return
	}
	for _, rule := range state.RouteRules {
		_ = rule.Rule.Close()
	}
	for _, rs := range state.RuleSetMap {
		_ = rs.Close()
	}
}

func (s *matchService) buildState(configSt os.FileInfo, dbSt os.FileInfo) (*matchState, error) {
	cfg, cfgFileSt, cfgRaw, err := loadConfig(s.configPath)
	if err != nil {
		return nil, err
	}
	if cfgFileSt != nil {
		configSt = cfgFileSt
	}
	ruleNamesFromConfig := extractRuleNamesFromConfigJSON(cfgRaw)

	usedRuleSetTags := collectUsedRuleSetTags(cfg.Route.Rules)
	activeRuleSets := filterRuleSetsByUsage(cfg.Route.RuleSet, usedRuleSetTags)

	remoteTags := wantRemoteRuleSetTags(activeRuleSets)
	remoteValues := map[string][]byte{}
	if len(remoteTags) > 0 {
		values, realDBSt, err := loadRemoteRuleSetValues(s.dbPath, remoteTags)
		if err != nil {
			return nil, err
		}
		remoteValues = values
		dbSt = realDBSt
	}

	ctx := context.Background()
	ruleSetMap := make(map[string]adapter.RuleSet, len(activeRuleSets))
	ruleSetInfo := make(map[string]option.RuleSet, len(activeRuleSets))
	ruleSets := make([]compiledRuleSet, 0, len(activeRuleSets))
	localFiles := make([]localFileStamp, 0)

	for i, rs := range activeRuleSets {
		if rs.Tag == "" {
			continue
		}
		compiled, localStamp, err := compileRuleSetFromOption(ctx, rs, s.configPath, remoteValues)
		if err != nil {
			return nil, fmt.Errorf("rule_set[%d] %q: %w", i, rs.Tag, err)
		}
		ruleSets = append(ruleSets, compiledRuleSet{Tag: rs.Tag, Rules: compiled})
		ruleSetMap[rs.Tag] = newStaticRuleSet(rs.Tag, compiled)
		ruleSetInfo[rs.Tag] = rs
		if localStamp != nil {
			localFiles = append(localFiles, *localStamp)
		}
	}

	sort.Slice(ruleSets, func(i, j int) bool { return ruleSets[i].Tag < ruleSets[j].Tag })
	sort.Slice(localFiles, func(i, j int) bool { return localFiles[i].Path < localFiles[j].Path })

	outboundType := make(map[string]string, len(cfg.Outbounds))
	outboundNames := map[string]string{
		"direct":     "direct",
		"direct-out": "direct",
		"block":      "block",
		"block-out":  "block",
	}
	routeOutboundNames := map[string]string{}
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "" {
			continue
		}
		outboundType[ob.Tag] = ob.Type
		outboundNames[ob.Tag] = normalizeOutboundName(ob.Tag)
	}
	homeproxyPath := ""
	const homeproxyConfigPath = "/etc/config/homeproxy"
	if st, err := os.Stat(homeproxyConfigPath); err == nil && st.Mode().IsRegular() {
		homeproxyPath = homeproxyConfigPath
	}
	var hpMeta *homeproxyMeta
	var homeproxySt os.FileInfo
	if homeproxyPath != "" {
		hpMeta, _ = loadHomeproxyMeta(homeproxyPath)
		if st, err := os.Stat(homeproxyPath); err == nil {
			homeproxySt = st
		}
	}
	uciRuleNames := []string(nil)
	if hpMeta != nil {
		for tag, name := range hpMeta.OutboundNameByTag {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			outboundNames[tag] = name
		}
		for tag, name := range hpMeta.RouteOutboundNameByTag {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			routeOutboundNames[tag] = name
		}
		uciRuleNames = hpMeta.RoutingRuleNames
	}

	outboundManager := newStubOutboundManager(cfg.Outbounds, cfg.Route.Final)
	router := &stubRouter{
		ruleSetMap: ruleSetMap,
	}
	ruleCtx := context.Background()
	ruleCtx = service.ContextWith[adapter.Router](ruleCtx, router)
	ruleCtx = service.ContextWith[adapter.OutboundManager](ruleCtx, outboundManager)
	ruleCtx = service.ContextWith[adapter.NetworkManager](ruleCtx, (*stubNetworkManager)(nil))

	logger := boxlog.NewNOPFactory().Logger()
	routeRules := make([]compiledRouteRule, 0, len(cfg.Route.Rules))
	routerRules := make([]adapter.Rule, 0, len(cfg.Route.Rules))
	for i, ruleOptions := range cfg.Route.Rules {
		r, err := routeRule.NewRule(ruleCtx, logger, ruleOptions, false)
		if err != nil {
			return nil, fmt.Errorf("route.rules[%d] parse: %w", i, err)
		}
		if err := r.Start(); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("route.rules[%d] start: %w", i, err)
		}
		routeRules = append(routeRules, compiledRouteRule{
			Index: i,
			Rule:  r,
		})
		routerRules = append(routerRules, r)
	}
	router.rules = routerRules
	ruleNames := buildRuleNameIndex(len(routeRules), ruleNamesFromConfig, uciRuleNames)

	cfgSize := int64(0)
	cfgMTime := time.Time{}
	if configSt != nil {
		cfgSize = configSt.Size()
		cfgMTime = configSt.ModTime()
	}

	state := &matchState{
		LoadedAt: time.Now(),

		DBPath: s.dbPath,

		ConfigPath:    s.configPath,
		ConfigSize:    cfgSize,
		ConfigModTime: cfgMTime,
		HomeproxyPath: homeproxyPath,
		LocalFiles:    localFiles,

		RouteFinal:        cfg.Route.Final,
		DefaultTag:        outboundManager.defaultTag,
		OutboundType:      outboundType,
		OutboundName:      outboundNames,
		RouteOutboundName: routeOutboundNames,

		RuleSetInfo: ruleSetInfo,
		RuleSets:    ruleSets,
		RuleSetMap:  ruleSetMap,
		RouteRules:  routeRules,
		RuleNames:   ruleNames,
	}
	if homeproxySt != nil {
		state.HomeproxySize = homeproxySt.Size()
		state.HomeproxyMTime = homeproxySt.ModTime()
	}
	if dbSt != nil {
		state.DBSize = dbSt.Size()
		state.DBModTime = dbSt.ModTime()
	}
	return state, nil
}

func (s *matchService) reloadIfNeeded() error {
	if s.ecoMode {
		return nil
	}
	need, cfgSt, dbSt, err := s.needsReload()
	if err != nil {
		return err
	}
	if !need {
		return nil
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	need, cfgSt, dbSt, err = s.needsReload()
	if err != nil {
		return err
	}
	if !need {
		return nil
	}

	newState, err := s.buildState(cfgSt, dbSt)
	if err != nil {
		return err
	}
	old := s.state.Load()
	s.state.Store(newState)
	closeMatchState(old)
	return nil
}

func (s *matchService) getStateForRequest() (*matchState, func(), error) {
	if s.ecoMode {
		cfgSt, err := os.Stat(s.configPath)
		if err != nil {
			return nil, nil, err
		}
		dbSt, _ := os.Stat(s.dbPath)
		state, err := s.buildState(cfgSt, dbSt)
		if err != nil {
			return nil, nil, err
		}
		return state, func() { closeMatchState(state) }, nil
	}
	if err := s.reloadIfNeeded(); err != nil {
		if state := s.state.Load(); state != nil && errors.Is(err, os.ErrNotExist) {
			return state, func() {}, nil
		}
		return nil, nil, err
	}
	state := s.state.Load()
	if state == nil {
		return nil, nil, fmt.Errorf("not loaded")
	}
	return state, func() {}, nil
}

type staticRuleSet struct {
	tag  string
	text string

	rules []adapter.HeadlessRule
	refs  atomic.Int32
}

func newStaticRuleSet(tag string, rules []adapter.HeadlessRule) *staticRuleSet {
	texts := make([]string, 0, len(rules))
	for _, r := range rules {
		texts = append(texts, r.String())
	}
	return &staticRuleSet{
		tag:   tag,
		text:  strings.Join(texts, " "),
		rules: rules,
	}
}

func (s *staticRuleSet) Name() string   { return s.tag }
func (s *staticRuleSet) String() string { return s.text }
func (s *staticRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	return nil
}
func (s *staticRuleSet) PostStart() error                  { return nil }
func (s *staticRuleSet) Metadata() adapter.RuleSetMetadata { return adapter.RuleSetMetadata{} }
func (s *staticRuleSet) ExtractIPSet() []*netipx.IPSet     { return nil }
func (s *staticRuleSet) IncRef()                           { s.refs.Add(1) }
func (s *staticRuleSet) DecRef()                           { _ = s.refs.Add(-1) }
func (s *staticRuleSet) Cleanup()                          {}
func (s *staticRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	return nil
}
func (s *staticRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {}
func (s *staticRuleSet) Close() error {
	s.rules = nil
	return nil
}
func (s *staticRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, r := range s.rules {
		if r.Match(metadata) {
			return true
		}
	}
	return false
}

type stubOutbound struct {
	tag          string
	outboundType string
}

func (s *stubOutbound) Type() string           { return s.outboundType }
func (s *stubOutbound) Tag() string            { return s.tag }
func (s *stubOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (s *stubOutbound) Dependencies() []string { return nil }
func (s *stubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial not supported")
}
func (s *stubOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen packet not supported")
}
func (s *stubOutbound) PreferredDomain(domain string) bool       { return false }
func (s *stubOutbound) PreferredAddress(address netip.Addr) bool { return false }

type stubOutboundManager struct {
	outbounds   []adapter.Outbound
	outboundMap map[string]adapter.Outbound
	defaultTag  string
}

func newStubOutboundManager(outbounds []configOutbound, finalTag string) *stubOutboundManager {
	mgr := &stubOutboundManager{
		outboundMap: make(map[string]adapter.Outbound),
	}
	for _, ob := range outbounds {
		if ob.Tag == "" {
			continue
		}
		stub := &stubOutbound{
			tag:          ob.Tag,
			outboundType: ob.Type,
		}
		mgr.outboundMap[ob.Tag] = stub
		mgr.outbounds = append(mgr.outbounds, stub)
		if mgr.defaultTag == "" {
			mgr.defaultTag = ob.Tag
		}
	}
	if finalTag != "" {
		if _, ok := mgr.outboundMap[finalTag]; ok {
			mgr.defaultTag = finalTag
		}
	}
	return mgr
}

func (s *stubOutboundManager) Start(stage adapter.StartStage) error { return nil }
func (s *stubOutboundManager) Close() error                         { return nil }
func (s *stubOutboundManager) Outbounds() []adapter.Outbound        { return s.outbounds }
func (s *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	ob, ok := s.outboundMap[tag]
	return ob, ok
}
func (s *stubOutboundManager) Default() adapter.Outbound {
	if s.defaultTag == "" {
		return nil
	}
	return s.outboundMap[s.defaultTag]
}
func (s *stubOutboundManager) Remove(tag string) error { return errors.New("not supported") }
func (s *stubOutboundManager) Create(ctx context.Context, router adapter.Router, logger boxlog.ContextLogger, tag string, outboundType string, options any) error {
	return errors.New("not supported")
}

type stubNetworkManager struct{}

func (s *stubNetworkManager) Start(stage adapter.StartStage) error               { return nil }
func (s *stubNetworkManager) Close() error                                       { return nil }
func (s *stubNetworkManager) InterfaceFinder() control.InterfaceFinder           { return nil }
func (s *stubNetworkManager) UpdateInterfaces() error                            { return nil }
func (s *stubNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }
func (s *stubNetworkManager) NetworkInterfaces() []adapter.NetworkInterface      { return nil }
func (s *stubNetworkManager) AutoDetectInterface() bool                          { return false }
func (s *stubNetworkManager) AutoDetectInterfaceFunc() control.Func              { return nil }
func (s *stubNetworkManager) ProtectFunc() control.Func                          { return nil }
func (s *stubNetworkManager) DefaultOptions() adapter.NetworkOptions             { return adapter.NetworkOptions{} }
func (s *stubNetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error   { return nil }
func (s *stubNetworkManager) AutoRedirectOutputMark() uint32                     { return 0 }
func (s *stubNetworkManager) AutoRedirectOutputMarkFunc() control.Func           { return nil }
func (s *stubNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor           { return nil }
func (s *stubNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor      { return nil }
func (s *stubNetworkManager) PackageManager() tun.PackageManager                 { return nil }
func (s *stubNetworkManager) WIFIState() adapter.WIFIState                       { return adapter.WIFIState{} }
func (s *stubNetworkManager) ResetNetwork()                                      {}
func (s *stubNetworkManager) UpdateWIFIState()                                   {}

type stubRouter struct {
	rules      []adapter.Rule
	ruleSetMap map[string]adapter.RuleSet
}

func (s *stubRouter) Start(stage adapter.StartStage) error { return nil }
func (s *stubRouter) Close() error                         { return nil }
func (s *stubRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return errors.New("not supported")
}
func (s *stubRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return errors.New("not supported")
}
func (s *stubRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}
func (s *stubRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}
func (s *stubRouter) PreMatch(metadata adapter.InboundContext) error { return nil }
func (s *stubRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	rs, ok := s.ruleSetMap[tag]
	return rs, ok
}
func (s *stubRouter) NeedWIFIState() bool                             { return false }
func (s *stubRouter) Rules() []adapter.Rule                           { return s.rules }
func (s *stubRouter) AppendTracker(tracker adapter.ConnectionTracker) {}
func (s *stubRouter) ResetNetwork()                                   {}

type httpMatchResponse struct {
	DBPath      string    `json:"dbPath"`
	DBModTime   time.Time `json:"dbModTime"`
	LoadedAt    time.Time `json:"loadedAt"`
	ConfigPath  string    `json:"configPath"`
	ConfigMTime time.Time `json:"configModTime"`

	Input     string `json:"input"`
	InputType string `json:"inputType"`

	Matches []httpMatchItem `json:"matches"`
}

type httpMatchItem struct {
	Tag      string `json:"tag"`
	ShortTag string `json:"shortTag"`
	URL      string `json:"url,omitempty"`
}

type checkRequest struct {
	Domains []string `json:"domains,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	Inbound string   `json:"inbound,omitempty"`
	Network string   `json:"network,omitempty"`
	Port    uint16   `json:"port,omitempty"`
}

type checkResult struct {
	Input      string `json:"input"`
	Normalized string `json:"normalized"`
	InputType  string `json:"inputType"`

	Class       string `json:"class"`
	Outbound    string `json:"outbound,omitempty"`
	OutboundTag string `json:"outboundTag,omitempty"`

	Matched    bool   `json:"matched"`
	RuleIndex  int    `json:"ruleIndex"`
	RuleName   string `json:"ruleName,omitempty"`
	Action     string `json:"action,omitempty"`
	ActionType string `json:"actionType,omitempty"`
	RuleExpr   string `json:"ruleExpr,omitempty"`

	Error string `json:"error,omitempty"`
}

type checkResponse struct {
	Mode        string        `json:"mode"`
	LoadedAt    time.Time     `json:"loadedAt"`
	ConfigPath  string        `json:"configPath"`
	ConfigMTime time.Time     `json:"configModTime"`
	DBPath      string        `json:"dbPath"`
	DBModTime   time.Time     `json:"dbModTime"`
	RuleSets    int           `json:"ruleSets"`
	RouteRules  int           `json:"routeRules"`
	Results     []checkResult `json:"results"`
}

func normalizeInput(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if h := u.Hostname(); h != "" {
				s = h
			}
		}
	} else {
		if u, err := url.Parse("x://" + s); err == nil {
			if h := u.Hostname(); h != "" {
				s = h
			}
		}
	}
	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	return strings.ToLower(s)
}

func safeMatch(rule adapter.Rule, meta *adapter.InboundContext) (matched bool, panicErr error) {
	defer func() {
		if r := recover(); r != nil {
			panicErr = fmt.Errorf("%v", r)
			matched = false
		}
	}()
	matched = rule.Match(meta)
	return
}

func classifyOutbound(state *matchState, outbound string) string {
	if outbound == "" {
		return "unknown"
	}
	obType := strings.ToLower(state.OutboundType[outbound])
	switch obType {
	case "block":
		return "block"
	case "direct":
		return "direct"
	}
	lTag := strings.ToLower(outbound)
	if strings.Contains(lTag, "block") || strings.Contains(lTag, "reject") {
		return "block"
	}
	if strings.Contains(lTag, "direct") {
		return "direct"
	}
	return "proxy"
}

func outboundDisplayName(state *matchState, outboundTag string) string {
	if state != nil {
		if name := strings.TrimSpace(state.OutboundName[outboundTag]); name != "" {
			return name
		}
	}
	return normalizeOutboundName(outboundTag)
}

func routeOutboundDisplayName(state *matchState, outboundTag string) string {
	if state != nil {
		if name := strings.TrimSpace(state.RouteOutboundName[outboundTag]); name != "" {
			return name
		}
	}
	return outboundDisplayName(state, outboundTag)
}

func (s *matchService) evaluateOne(state *matchState, input string, inbound string, network string, port uint16) checkResult {
	res := checkResult{
		Input:     input,
		RuleIndex: -1,
	}
	normalized := normalizeInput(input)
	res.Normalized = normalized
	if normalized == "" {
		res.Error = "empty input"
		return res
	}

	meta := buildMetadata(normalized)
	if meta.Domain == "" {
		res.InputType = "ip"
	} else {
		res.InputType = "domain"
	}
	if inbound == "" {
		inbound = "redirect-in"
	}
	if network == "" {
		network = N.NetworkTCP
	}
	meta.Inbound = inbound
	meta.Network = network
	if port > 0 {
		if meta.Domain != "" {
			meta.Destination = M.ParseSocksaddrHostPort(meta.Domain, port)
		} else if meta.Destination.IsValid() {
			meta.Destination.Port = port
		}
	}

	finalOutbound := state.RouteFinal
	if finalOutbound == "" {
		finalOutbound = state.DefaultTag
	}
	res.OutboundTag = finalOutbound
	res.Outbound = outboundDisplayName(state, finalOutbound)
	res.Class = classifyOutbound(state, finalOutbound)
	res.ActionType = "final"
	res.Action = "final"

	for _, routeItem := range state.RouteRules {
		metaCopy := meta
		metaCopy.ResetRuleCache()

		matched, panicErr := safeMatch(routeItem.Rule, &metaCopy)
		if panicErr != nil {
			res.Error = "rule match panic: " + panicErr.Error()
			return res
		}
		if !matched {
			continue
		}
		action := routeItem.Rule.Action()
		if action == nil {
			continue
		}
		if !adapter.IsFinalAction(action) {
			continue
		}
		res.Matched = true
		res.RuleIndex = routeItem.Index
		if ruleName := strings.TrimSpace(state.RuleNames[routeItem.Index]); ruleName != "" {
			res.RuleName = ruleName
		} else {
			res.RuleName = fmt.Sprintf("rule_%d", routeItem.Index)
		}
		res.ActionType = action.Type()
		res.Action = action.String()
		res.RuleExpr = routeItem.Rule.String()

		switch a := action.(type) {
		case *routeRule.RuleActionReject:
			res.Class = "block"
			res.OutboundTag = "block-out"
			res.Outbound = outboundDisplayName(state, "block-out")
		case *routeRule.RuleActionRoute:
			res.OutboundTag = a.Outbound
			res.Class = classifyOutbound(state, a.Outbound)
			if res.Class == "proxy" {
				res.Outbound = routeOutboundDisplayName(state, a.Outbound)
			} else {
				res.Outbound = outboundDisplayName(state, a.Outbound)
			}
		case *routeRule.RuleActionDirect:
			res.OutboundTag = "direct"
			res.Outbound = outboundDisplayName(state, "direct")
			res.Class = "direct"
		default:
			// keep defaults
		}
		return res
	}
	return res
}

func parseBearerToken(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}
	parts := strings.Fields(authHeader)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return authHeader
}

func (s *matchService) authorized(r *http.Request) bool {
	expected := strings.TrimSpace(s.accessToken)
	if expected == "" {
		return true
	}

	candidates := []string{
		strings.TrimSpace(r.URL.Query().Get("access_token")),
		strings.TrimSpace(r.URL.Query().Get("token")),
		strings.TrimSpace(r.Header.Get("X-Access-Token")),
		parseBearerToken(r.Header.Get("Authorization")),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func (s *matchService) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	if s.authorized(r) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": "missing or invalid access token",
	})
	return false
}

func (s *matchService) handleMatch(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	q := r.URL.Query().Get("q")
	if q == "" {
		q = r.URL.Query().Get("domain")
	}
	if q == "" {
		q = r.URL.Query().Get("ip")
	}
	if q == "" {
		http.Error(w, "missing query param: q", http.StatusBadRequest)
		return
	}
	state, done, err := s.getStateForRequest()
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer done()

	meta := buildMetadata(normalizeInput(q))
	inputType := "domain"
	if meta.Domain == "" {
		inputType = "ip"
	}

	matches := make([]httpMatchItem, 0)
	for _, rs := range state.RuleSets {
		if matchAny(rs.Rules, &meta) {
			item := httpMatchItem{
				Tag:      rs.Tag,
				ShortTag: shortTag(rs.Tag),
			}
			if info, ok := state.RuleSetInfo[rs.Tag]; ok && info.Type == "remote" {
				item.URL = info.RemoteOptions.URL
			}
			matches = append(matches, item)
		}
	}

	resp := httpMatchResponse{
		DBPath:      state.DBPath,
		DBModTime:   state.DBModTime,
		LoadedAt:    state.LoadedAt,
		ConfigPath:  state.ConfigPath,
		ConfigMTime: state.ConfigModTime,
		Input:       q,
		InputType:   inputType,
		Matches:     matches,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	state, done, err := s.getStateForRequest()
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer done()

	var req checkRequest
	if r.Method == http.MethodGet {
		if q := r.URL.Query().Get("q"); q != "" {
			req.Domains = strings.Split(q, ",")
		}
		if req.Domain == "" {
			req.Domain = r.URL.Query().Get("domain")
		}
		req.Inbound = r.URL.Query().Get("inbound")
		req.Network = r.URL.Query().Get("network")
		if req.Port == 0 {
			var p uint16
			_, _ = fmt.Sscanf(r.URL.Query().Get("port"), "%d", &p)
			req.Port = p
		}
	} else {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Domain != "" {
		req.Domains = append(req.Domains, req.Domain)
	}
	if len(req.Domains) == 0 {
		http.Error(w, "missing domains", http.StatusBadRequest)
		return
	}
	if len(req.Domains) > 1024 {
		http.Error(w, "too many domains (max 1024)", http.StatusBadRequest)
		return
	}

	results := make([]checkResult, 0, len(req.Domains))
	for _, domain := range req.Domains {
		results = append(results, s.evaluateOne(state, domain, req.Inbound, req.Network, req.Port))
	}

	resp := checkResponse{
		Mode:        s.mode,
		LoadedAt:    state.LoadedAt,
		ConfigPath:  state.ConfigPath,
		ConfigMTime: state.ConfigModTime,
		DBPath:      state.DBPath,
		DBModTime:   state.DBModTime,
		RuleSets:    len(state.RuleSets),
		RouteRules:  len(state.RouteRules),
		Results:     results,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	state, done, err := s.getStateForRequest()
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer done()
	type resp struct {
		Mode          string    `json:"mode"`
		DBPath        string    `json:"dbPath"`
		DBSize        int64     `json:"dbSize"`
		DBModTime     time.Time `json:"dbModTime"`
		ConfigPath    string    `json:"configPath"`
		ConfigSize    int64     `json:"configSize"`
		ConfigModTime time.Time `json:"configModTime"`
		LoadedAt      time.Time `json:"loadedAt"`
		RuleSets      int       `json:"ruleSets"`
		RouteRules    int       `json:"routeRules"`
		LocalFiles    int       `json:"localFiles"`
	}
	out := resp{
		Mode:          s.mode,
		DBPath:        state.DBPath,
		DBSize:        state.DBSize,
		DBModTime:     state.DBModTime,
		ConfigPath:    state.ConfigPath,
		ConfigSize:    state.ConfigSize,
		ConfigModTime: state.ConfigModTime,
		LoadedAt:      state.LoadedAt,
		RuleSets:      len(state.RuleSets),
		RouteRules:    len(state.RouteRules),
		LocalFiles:    len(state.LocalFiles),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func (s *matchService) serve(listen string) error {
	if listen == "" {
		return fmt.Errorf("missing listen address")
	}
	if s.mode == "" {
		s.mode = "default"
	}
	if !s.ecoMode {
		if err := s.reloadIfNeeded(); err != nil {
			fmt.Fprintf(os.Stderr, "initial state load skipped: %v\n", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/match", s.handleMatch)
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/rules", s.handleRulesList)
	mux.HandleFunc("/rules/create", s.handleRulesCreate)
	mux.HandleFunc("/rules/delete", s.handleRulesDelete)
	mux.HandleFunc("/rules/update", s.handleRulesUpdate)
	mux.HandleFunc("/rules/hot-reload", s.handleRulesHotReload)
	mux.HandleFunc("/routing/nodes", s.handleRoutingNodesList)
	mux.HandleFunc("/rulesets", s.handleRuleSetsList)
	mux.HandleFunc("/devices", s.handleDevicesList)
	mux.HandleFunc("/homeproxy/status", s.handleHomeproxyStatus)
	mux.HandleFunc("/homeproxy/start", s.handleHomeproxyStart)
	mux.HandleFunc("/homeproxy/stop", s.handleHomeproxyStop)
	mux.HandleFunc("/homeproxy/restart", s.handleHomeproxyRestart)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "listening on http://%s (mode=%s)\n", ln.Addr().String(), s.mode)
	return server.Serve(ln)
}
