package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	homeproxyUCIConfigPath       = "/etc/config/homeproxy"
	homeproxyGenerateClientUCode = "/etc/homeproxy/scripts/generate_client.uc"
	homeproxyClientConfigPath    = "/var/run/homeproxy/sing-box-c.json"
)

type uciSection struct {
	Type    string
	Name    string
	Options map[string]string
	Lists   map[string][]string
}

type ruleSetRef struct {
	ID   string `json:"id"`
	Tag  string `json:"tag"`
	Name string `json:"name"`
}

type ruleHostIPConfig struct {
	Domain        []string `json:"domain"`
	DomainSuffix  []string `json:"domainSuffix"`
	DomainKeyword []string `json:"domainKeyword"`
	DomainRegex   []string `json:"domainRegex"`
	IPCIDR        []string `json:"ipCidr"`
	SourceIPCIDR  []string `json:"sourceIpCidr"`
}

type rulePortConfig struct {
	SourcePort      []string `json:"sourcePort"`
	SourcePortRange []string `json:"sourcePortRange"`
	Port            []string `json:"port"`
	PortRange       []string `json:"portRange"`
}

type ruleOutboundInfo struct {
	Action string `json:"action"`
	Class  string `json:"class"`
	Tag    string `json:"tag,omitempty"`
	Name   string `json:"name,omitempty"`
	UCITag string `json:"uciTag,omitempty"`
}

type routingRuleView struct {
	ID       string           `json:"id"`
	Tag      string           `json:"tag"`
	Name     string           `json:"name"`
	Enabled  bool             `json:"enabled"`
	RuleSet  []ruleSetRef     `json:"ruleSet"`
	HostIP   ruleHostIPConfig `json:"hostIp"`
	Port     rulePortConfig   `json:"port"`
	Outbound ruleOutboundInfo `json:"outbound"`
}

type rulesListResponse struct {
	ConfigPath string              `json:"configPath"`
	Fields     map[string][]string `json:"fields"`
	Rules      []routingRuleView   `json:"rules"`
}

type rulesUpdatePayload struct {
	RuleSet              []string `json:"ruleSet,omitempty"`
	RuleSetSnake         []string `json:"rule_set,omitempty"`
	Domain               []string `json:"domain,omitempty"`
	DomainSuffix         []string `json:"domainSuffix,omitempty"`
	DomainSuffixSnake    []string `json:"domain_suffix,omitempty"`
	DomainKeyword        []string `json:"domainKeyword,omitempty"`
	DomainKeywordSnake   []string `json:"domain_keyword,omitempty"`
	DomainRegex          []string `json:"domainRegex,omitempty"`
	DomainRegexSnake     []string `json:"domain_regex,omitempty"`
	IPCIDR               []string `json:"ipCidr,omitempty"`
	IPCIDRSnake          []string `json:"ip_cidr,omitempty"`
	SourceIPCIDR         []string `json:"sourceIpCidr,omitempty"`
	SourceIPCIDRSnake    []string `json:"source_ip_cidr,omitempty"`
	SourcePort           []string `json:"sourcePort,omitempty"`
	SourcePortSnake      []string `json:"source_port,omitempty"`
	SourcePortRange      []string `json:"sourcePortRange,omitempty"`
	SourcePortRangeSnake []string `json:"source_port_range,omitempty"`
	Port                 []string `json:"port,omitempty"`
	PortRange            []string `json:"portRange,omitempty"`
	PortRangeSnake       []string `json:"port_range,omitempty"`
}

type rulesUpdateRequest struct {
	Tag    string             `json:"tag,omitempty"`
	ID     string             `json:"id,omitempty"`
	Config rulesUpdatePayload `json:"config"`
}

type rulesUpdateResponse struct {
	Updated   bool      `json:"updated"`
	Applied   bool      `json:"applied"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type rulesHotReloadResponse struct {
	Generated  bool      `json:"generated"`
	Checked    bool      `json:"checked"`
	Signaled   bool      `json:"signaled"`
	Signal     string    `json:"signal"`
	Service    string    `json:"service"`
	Instance   string    `json:"instance"`
	Config     string    `json:"config"`
	ReloadedAt time.Time `json:"reloadedAt"`
}

type homeproxyServiceStatusResponse struct {
	Running   bool      `json:"running"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checkedAt"`
}

type homeproxyServiceActionResponse struct {
	Action    string    `json:"action"`
	OK        bool      `json:"ok"`
	Running   bool      `json:"running"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checkedAt"`
}

type normalizedRuleConfig struct {
	RuleSet         []string
	Domain          []string
	DomainSuffix    []string
	DomainKeyword   []string
	DomainRegex     []string
	IPCIDR          []string
	SourceIPCIDR    []string
	SourcePort      []string
	SourcePortRange []string
	Port            []string
	PortRange       []string
}

func parseListLine(line string) (key string, value string, ok bool) {
	if !strings.HasPrefix(line, "list ") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "list "))
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

func parseUCISections(path string) ([]uciSection, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sections := make([]uciSection, 0)
	var current *uciSection
	flush := func() {
		if current == nil {
			return
		}
		sections = append(sections, *current)
	}

	for _, raw := range strings.Split(string(content), "\n") {
		line := stripInlineComment(strings.TrimSpace(raw))
		if line == "" {
			continue
		}
		if st, sn, ok := parseConfigLine(line); ok {
			flush()
			current = &uciSection{
				Type:    st,
				Name:    sn,
				Options: make(map[string]string),
				Lists:   make(map[string][]string),
			}
			continue
		}
		if current == nil {
			continue
		}
		if key, value, ok := parseOptionLine(line); ok {
			current.Options[key] = value
			continue
		}
		if key, value, ok := parseListLine(line); ok {
			current.Lists[key] = append(current.Lists[key], value)
			continue
		}
	}
	flush()
	return sections, nil
}

func cloneList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func sectionListValue(section uciSection, key string) []string {
	if values, ok := section.Lists[key]; ok && len(values) > 0 {
		return cloneList(values)
	}
	if value := strings.TrimSpace(section.Options[key]); value != "" {
		return []string{value}
	}
	return []string{}
}

func routingRuleTag(section string) string {
	return "cfg-" + section + "-rule"
}

func routingSectionFromAnyTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "cfg-") && strings.HasSuffix(value, "-rule") && len(value) > len("cfg--rule") {
		return value[len("cfg-") : len(value)-len("-rule")]
	}
	return value
}

func resolveRoutingOutbound(actionRaw string, outboundRaw string, outboundLabels map[string]string) ruleOutboundInfo {
	action := strings.TrimSpace(actionRaw)
	if action == "" {
		action = "route"
	}
	info := ruleOutboundInfo{
		Action: action,
	}
	switch action {
	case "reject":
		info.Class = "block"
		info.Tag = "block-out"
		info.Name = "block"
		return info
	case "route", "route-options":
	default:
		info.Class = action
		return info
	}

	outboundRaw = strings.TrimSpace(outboundRaw)
	if outboundRaw == "" {
		outboundRaw = "direct-out"
	}
	switch strings.ToLower(outboundRaw) {
	case "direct", "direct-out":
		info.Class = "direct"
		info.Tag = "direct-out"
		info.Name = "Direct"
		return info
	case "block", "block-out", "reject", "reject-out":
		info.Class = "block"
		info.Tag = "block-out"
		info.Name = "block"
		return info
	}

	if strings.HasPrefix(outboundRaw, "cfg-") && strings.HasSuffix(outboundRaw, "-out") && len(outboundRaw) > len("cfg--out") {
		uciTag := outboundRaw[len("cfg-") : len(outboundRaw)-len("-out")]
		info.UCITag = uciTag
		info.Tag = outboundRaw
	} else if strings.HasSuffix(outboundRaw, "-out") {
		info.Tag = outboundRaw
	} else {
		info.UCITag = outboundRaw
		info.Tag = "cfg-" + outboundRaw + "-out"
	}

	if info.UCITag != "" {
		if name := strings.TrimSpace(outboundLabels[info.UCITag]); name != "" {
			info.Name = name
		}
	}
	if info.Name == "" {
		info.Name = normalizeOutboundName(info.Tag)
	}
	info.Class = "proxy"
	if strings.Contains(strings.ToLower(info.Tag), "direct") {
		info.Class = "direct"
	}
	if strings.Contains(strings.ToLower(info.Tag), "block") || strings.Contains(strings.ToLower(info.Tag), "reject") {
		info.Class = "block"
	}
	return info
}

func normalizeList(values []string, limit int) []string {
	if limit <= 0 {
		limit = 4096
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func firstNonEmpty(primary []string, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func (p rulesUpdatePayload) normalize() normalizedRuleConfig {
	return normalizedRuleConfig{
		RuleSet:         normalizeList(firstNonEmpty(p.RuleSet, p.RuleSetSnake), 1024),
		Domain:          normalizeList(p.Domain, 4096),
		DomainSuffix:    normalizeList(firstNonEmpty(p.DomainSuffix, p.DomainSuffixSnake), 4096),
		DomainKeyword:   normalizeList(firstNonEmpty(p.DomainKeyword, p.DomainKeywordSnake), 4096),
		DomainRegex:     normalizeList(firstNonEmpty(p.DomainRegex, p.DomainRegexSnake), 4096),
		IPCIDR:          normalizeList(firstNonEmpty(p.IPCIDR, p.IPCIDRSnake), 4096),
		SourceIPCIDR:    normalizeList(firstNonEmpty(p.SourceIPCIDR, p.SourceIPCIDRSnake), 4096),
		SourcePort:      normalizeList(firstNonEmpty(p.SourcePort, p.SourcePortSnake), 1024),
		SourcePortRange: normalizeList(firstNonEmpty(p.SourcePortRange, p.SourcePortRangeSnake), 1024),
		Port:            normalizeList(p.Port, 1024),
		PortRange:       normalizeList(firstNonEmpty(p.PortRange, p.PortRangeSnake), 1024),
	}
}

func runCommandCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), fmt.Errorf("%s: %s", name, msg)
	}
	return string(out), nil
}

func updateRuleListsInUCI(ruleID string, cfg normalizedRuleConfig) error {
	sectionTypeOut, err := runCommandCombined("uci", "-q", "get", "homeproxy."+ruleID)
	if err != nil {
		return fmt.Errorf("rule %q not found: %w", ruleID, err)
	}
	if strings.TrimSpace(sectionTypeOut) != "routing_rule" {
		return fmt.Errorf("%q is not a routing_rule section", ruleID)
	}

	managed := map[string][]string{
		"rule_set":          cfg.RuleSet,
		"domain":            cfg.Domain,
		"domain_suffix":     cfg.DomainSuffix,
		"domain_keyword":    cfg.DomainKeyword,
		"domain_regex":      cfg.DomainRegex,
		"ip_cidr":           cfg.IPCIDR,
		"source_ip_cidr":    cfg.SourceIPCIDR,
		"source_port":       cfg.SourcePort,
		"source_port_range": cfg.SourcePortRange,
		"port":              cfg.Port,
		"port_range":        cfg.PortRange,
	}

	for key, values := range managed {
		_, _ = runCommandCombined("uci", "-q", "delete", fmt.Sprintf("homeproxy.%s.%s", ruleID, key))
		for _, value := range values {
			_, err = runCommandCombined("uci", "-q", "add_list", fmt.Sprintf("homeproxy.%s.%s=%s", ruleID, key, value))
			if err != nil {
				return fmt.Errorf("set %s failed: %w", key, err)
			}
		}
	}
	_, err = runCommandCombined("uci", "-q", "commit", "homeproxy")
	if err != nil {
		return fmt.Errorf("uci commit failed: %w", err)
	}
	return nil
}

func listRuleSetMeta(sections []uciSection) map[string]ruleSetRef {
	meta := make(map[string]ruleSetRef)
	for _, section := range sections {
		if section.Type != "ruleset" {
			continue
		}
		name := strings.TrimSpace(section.Options["label"])
		if name == "" {
			name = section.Name
		}
		meta[section.Name] = ruleSetRef{
			ID:   section.Name,
			Tag:  routingRuleTag(section.Name),
			Name: name,
		}
	}
	return meta
}

func listOutboundLabels(sections []uciSection) map[string]string {
	labels := make(map[string]string)
	for _, section := range sections {
		if section.Type != "routing_node" {
			continue
		}
		label := strings.TrimSpace(section.Options["label"])
		if label == "" {
			label = section.Name
		}
		labels[section.Name] = label
	}
	return labels
}

func (s *matchService) handleRulesList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ruleSetMeta := listRuleSetMeta(sections)
	outboundLabels := listOutboundLabels(sections)

	rules := make([]routingRuleView, 0)
	for _, section := range sections {
		if section.Type != "routing_rule" {
			continue
		}
		name := strings.TrimSpace(section.Options["label"])
		if name == "" {
			name = section.Name
		}
		enabled := strings.TrimSpace(section.Options["enabled"]) != "0"

		ruleSetRefs := make([]ruleSetRef, 0)
		for _, id := range sectionListValue(section, "rule_set") {
			if rs, ok := ruleSetMeta[id]; ok {
				ruleSetRefs = append(ruleSetRefs, rs)
				continue
			}
			ruleSetRefs = append(ruleSetRefs, ruleSetRef{
				ID:   id,
				Tag:  routingRuleTag(id),
				Name: id,
			})
		}

		rules = append(rules, routingRuleView{
			ID:      section.Name,
			Tag:     routingRuleTag(section.Name),
			Name:    name,
			Enabled: enabled,
			RuleSet: ruleSetRefs,
			HostIP: ruleHostIPConfig{
				Domain:        sectionListValue(section, "domain"),
				DomainSuffix:  sectionListValue(section, "domain_suffix"),
				DomainKeyword: sectionListValue(section, "domain_keyword"),
				DomainRegex:   sectionListValue(section, "domain_regex"),
				IPCIDR:        sectionListValue(section, "ip_cidr"),
				SourceIPCIDR:  sectionListValue(section, "source_ip_cidr"),
			},
			Port: rulePortConfig{
				SourcePort:      sectionListValue(section, "source_port"),
				SourcePortRange: sectionListValue(section, "source_port_range"),
				Port:            sectionListValue(section, "port"),
				PortRange:       sectionListValue(section, "port_range"),
			},
			Outbound: resolveRoutingOutbound(section.Options["action"], section.Options["outbound"], outboundLabels),
		})
	}

	resp := rulesListResponse{
		ConfigPath: homeproxyUCIConfigPath,
		Fields: map[string][]string{
			"ruleSet": {"rule_set"},
			"hostIp":  {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr"},
			"port":    {"source_port", "source_port_range", "port", "port_range"},
		},
		Rules: rules,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rulesUpdateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ruleID := routingSectionFromAnyTag(req.Tag)
	if ruleID == "" {
		ruleID = routingSectionFromAnyTag(req.ID)
	}
	if ruleID == "" {
		http.Error(w, "missing rule tag/id", http.StatusBadRequest)
		return
	}
	if strings.Contains(ruleID, " ") {
		http.Error(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	cfg := req.Config.normalize()
	if err := updateRuleListsInUCI(ruleID, cfg); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp := rulesUpdateResponse{
		Updated:   true,
		Applied:   false,
		ID:        ruleID,
		Tag:       routingRuleTag(ruleID),
		UpdatedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func detectSingBoxBinary() string {
	if _, err := os.Stat("/usr/bin/sing-box"); err == nil {
		return "/usr/bin/sing-box"
	}
	return "sing-box"
}

func (s *matchService) handleRulesHotReload(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := runCommandCombined("ucode", "-S", homeproxyGenerateClientUCode); err != nil {
		http.Error(w, "generate client config failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	singBoxBin := detectSingBoxBinary()
	if _, err := runCommandCombined(singBoxBin, "check", "--config", homeproxyClientConfigPath); err != nil {
		http.Error(w, "sing-box check failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := runCommandCombined("ubus", "call", "service", "signal", `{"name":"homeproxy","instance":"sing-box-c","signal":1}`); err != nil {
		http.Error(w, "ubus signal failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := rulesHotReloadResponse{
		Generated:  true,
		Checked:    true,
		Signaled:   true,
		Signal:     "SIGHUP",
		Service:    "homeproxy",
		Instance:   "sing-box-c",
		Config:     homeproxyClientConfigPath,
		ReloadedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func interpretHomeproxyStatus(text string) (bool, bool) {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" || lower == "unknown" {
		return false, false
	}
	if strings.Contains(lower, "not running") || strings.Contains(lower, "inactive") || strings.Contains(lower, "stopped") {
		return false, true
	}
	if strings.Contains(lower, "running") {
		return true, true
	}
	return false, false
}

func queryHomeproxyStatus() (bool, string, error) {
	cmd := exec.Command("/etc/init.d/homeproxy", "status")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text == "" {
		text = "unknown"
	}
	running, known := interpretHomeproxyStatus(text)
	if err == nil {
		if known {
			return running, text, nil
		}
		return false, text, nil
	}
	if known {
		return running, text, nil
	}
	return false, text, err
}

func runHomeproxyAction(action string) error {
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}

	cmd := exec.Command("/etc/init.d/homeproxy", action)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	lower := strings.ToLower(text)

	if err == nil {
		return nil
	}

	if action == "stop" {
		if strings.Contains(lower, "not running") || strings.Contains(lower, "inactive") || strings.Contains(lower, "not found") {
			return nil
		}
	}
	if action == "start" {
		if strings.Contains(lower, "already running") {
			return nil
		}
	}
	if action == "restart" {
		if strings.Contains(lower, "not running") || strings.Contains(lower, "inactive") || strings.Contains(lower, "not found") {
			if _, startErr := runCommandCombined("/etc/init.d/homeproxy", "start"); startErr == nil {
				return nil
			}
		}
	}

	if text == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, text)
}

func (s *matchService) handleHomeproxyStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	running, statusText, err := queryHomeproxyStatus()
	if err != nil {
		http.Error(w, "status failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := homeproxyServiceStatusResponse{
		Running:   running,
		Status:    statusText,
		CheckedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleHomeproxyAction(action string, w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := runHomeproxyAction(action); err != nil {
		http.Error(w, "action failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	running, statusText, err := queryHomeproxyStatus()
	if err != nil {
		http.Error(w, "status after action failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := homeproxyServiceActionResponse{
		Action:    action,
		OK:        true,
		Running:   running,
		Status:    statusText,
		CheckedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleHomeproxyStart(w http.ResponseWriter, r *http.Request) {
	s.handleHomeproxyAction("start", w, r)
}

func (s *matchService) handleHomeproxyStop(w http.ResponseWriter, r *http.Request) {
	s.handleHomeproxyAction("stop", w, r)
}

func (s *matchService) handleHomeproxyRestart(w http.ResponseWriter, r *http.Request) {
	s.handleHomeproxyAction("restart", w, r)
}
