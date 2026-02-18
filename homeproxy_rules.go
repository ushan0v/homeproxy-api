package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	homeproxyUCIConfigPath       = "/etc/config/homeproxy"
	homeproxyGenerateClientUCode = "/etc/homeproxy/scripts/generate_client.uc"
	homeproxyClientConfigPath    = "/var/run/homeproxy/sing-box-c.json"
	homeproxyDHCPLeasesPath      = "/tmp/dhcp.leases"
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
	RuleSet              *[]string `json:"ruleSet,omitempty"`
	RuleSetSnake         *[]string `json:"rule_set,omitempty"`
	Domain               *[]string `json:"domain,omitempty"`
	DomainSuffix         *[]string `json:"domainSuffix,omitempty"`
	DomainSuffixSnake    *[]string `json:"domain_suffix,omitempty"`
	DomainKeyword        *[]string `json:"domainKeyword,omitempty"`
	DomainKeywordSnake   *[]string `json:"domain_keyword,omitempty"`
	DomainRegex          *[]string `json:"domainRegex,omitempty"`
	DomainRegexSnake     *[]string `json:"domain_regex,omitempty"`
	IPCIDR               *[]string `json:"ipCidr,omitempty"`
	IPCIDRSnake          *[]string `json:"ip_cidr,omitempty"`
	SourceIPCIDR         *[]string `json:"sourceIpCidr,omitempty"`
	SourceIPCIDRSnake    *[]string `json:"source_ip_cidr,omitempty"`
	SourcePort           *[]string `json:"sourcePort,omitempty"`
	SourcePortSnake      *[]string `json:"source_port,omitempty"`
	SourcePortRange      *[]string `json:"sourcePortRange,omitempty"`
	SourcePortRangeSnake *[]string `json:"source_port_range,omitempty"`
	Port                 *[]string `json:"port,omitempty"`
	PortRange            *[]string `json:"portRange,omitempty"`
	PortRangeSnake       *[]string `json:"port_range,omitempty"`
}

type rulesUpdateOutbound struct {
	Class  string `json:"class,omitempty"`
	Node   string `json:"node,omitempty"`
	Tag    string `json:"tag,omitempty"`
	UCITag string `json:"uciTag,omitempty"`
}

type rulesUpdateRequest struct {
	Tag      string               `json:"tag,omitempty"`
	ID       string               `json:"id,omitempty"`
	Name     *string              `json:"name,omitempty"`
	Label    *string              `json:"label,omitempty"`
	Outbound *rulesUpdateOutbound `json:"outbound,omitempty"`
	Config   rulesUpdatePayload   `json:"config"`
}

type rulesUpdateResponse struct {
	Updated   bool      `json:"updated"`
	Applied   bool      `json:"applied"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type rulesCreateRequest struct {
	Tag      string               `json:"tag,omitempty"`
	ID       string               `json:"id,omitempty"`
	Name     *string              `json:"name,omitempty"`
	Label    *string              `json:"label,omitempty"`
	Enabled  *bool                `json:"enabled,omitempty"`
	Outbound *rulesUpdateOutbound `json:"outbound,omitempty"`
	Config   rulesUpdatePayload   `json:"config"`
}

type rulesCreateResponse struct {
	Created   bool      `json:"created"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	CreatedAt time.Time `json:"createdAt"`
}

type rulesDeleteRequest struct {
	Tag string `json:"tag,omitempty"`
	ID  string `json:"id,omitempty"`
}

type rulesDeleteResponse struct {
	Deleted   bool      `json:"deleted"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	DeletedAt time.Time `json:"deletedAt"`
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

type routingNodeView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Node        string `json:"node"`
	Tag         string `json:"tag"`
	OutboundTag string `json:"outboundTag"`
}

type routingNodesListResponse struct {
	ConfigPath string            `json:"configPath"`
	Nodes      []routingNodeView `json:"nodes"`
}

type ruleSetListItem struct {
	ID             string `json:"id"`
	Tag            string `json:"tag"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Type           string `json:"type,omitempty"`
	Format         string `json:"format,omitempty"`
	URL            string `json:"url,omitempty"`
	Path           string `json:"path,omitempty"`
	UpdateInterval string `json:"updateInterval,omitempty"`
	Outbound       string `json:"outbound,omitempty"`
}

type ruleSetsListResponse struct {
	ConfigPath string            `json:"configPath"`
	RuleSets   []ruleSetListItem `json:"ruleSets"`
}

type deviceLeaseView struct {
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	MAC           string    `json:"mac"`
	ClientID      string    `json:"clientId,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt,omitempty"`
	ExpiresAtUnix int64     `json:"expiresAtUnix,omitempty"`
	Expired       bool      `json:"expired"`
}

type devicesListResponse struct {
	LeasePath string            `json:"leasePath"`
	Devices   []deviceLeaseView `json:"devices"`
}

type listPatch struct {
	Set    bool
	Values []string
}

type normalizedRuleConfig struct {
	RuleSet         listPatch
	Domain          listPatch
	DomainSuffix    listPatch
	DomainKeyword   listPatch
	DomainRegex     listPatch
	IPCIDR          listPatch
	SourceIPCIDR    listPatch
	SourcePort      listPatch
	SourcePortRange listPatch
	Port            listPatch
	PortRange       listPatch
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

func chooseListPatch(primary *[]string, fallback *[]string, limit int) listPatch {
	src := primary
	if src == nil {
		src = fallback
	}
	if src == nil {
		return listPatch{}
	}
	return listPatch{
		Set:    true,
		Values: normalizeList(*src, limit),
	}
}

func chooseSingleListPatch(src *[]string, limit int) listPatch {
	if src == nil {
		return listPatch{}
	}
	return listPatch{
		Set:    true,
		Values: normalizeList(*src, limit),
	}
}

func (c normalizedRuleConfig) hasAny() bool {
	return c.RuleSet.Set ||
		c.Domain.Set ||
		c.DomainSuffix.Set ||
		c.DomainKeyword.Set ||
		c.DomainRegex.Set ||
		c.IPCIDR.Set ||
		c.SourceIPCIDR.Set ||
		c.SourcePort.Set ||
		c.SourcePortRange.Set ||
		c.Port.Set ||
		c.PortRange.Set
}

func (p rulesUpdatePayload) normalize() normalizedRuleConfig {
	return normalizedRuleConfig{
		RuleSet:         chooseListPatch(p.RuleSet, p.RuleSetSnake, 1024),
		Domain:          chooseSingleListPatch(p.Domain, 4096),
		DomainSuffix:    chooseListPatch(p.DomainSuffix, p.DomainSuffixSnake, 4096),
		DomainKeyword:   chooseListPatch(p.DomainKeyword, p.DomainKeywordSnake, 4096),
		DomainRegex:     chooseListPatch(p.DomainRegex, p.DomainRegexSnake, 4096),
		IPCIDR:          chooseListPatch(p.IPCIDR, p.IPCIDRSnake, 4096),
		SourceIPCIDR:    chooseListPatch(p.SourceIPCIDR, p.SourceIPCIDRSnake, 4096),
		SourcePort:      chooseListPatch(p.SourcePort, p.SourcePortSnake, 1024),
		SourcePortRange: chooseListPatch(p.SourcePortRange, p.SourcePortRangeSnake, 1024),
		Port:            chooseSingleListPatch(p.Port, 1024),
		PortRange:       chooseListPatch(p.PortRange, p.PortRangeSnake, 1024),
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

func getUCISectionType(sectionID string) (string, error) {
	out, err := runCommandCombined("uci", "-q", "get", "homeproxy."+sectionID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func ensureRoutingRuleSection(ruleID string) error {
	sectionType, err := getUCISectionType(ruleID)
	if err != nil {
		return fmt.Errorf("rule %q not found: %w", ruleID, err)
	}
	if sectionType != "routing_rule" {
		return fmt.Errorf("%q is not a routing_rule section", ruleID)
	}
	return nil
}

func setUCIOption(ruleID string, key string, value string) error {
	_, err := runCommandCombined("uci", "-q", "set", fmt.Sprintf("homeproxy.%s.%s=%s", ruleID, key, value))
	if err != nil {
		return fmt.Errorf("set %s failed: %w", key, err)
	}
	return nil
}

func deleteUCIOption(ruleID string, key string) error {
	_, err := runCommandCombined("uci", "-q", "delete", fmt.Sprintf("homeproxy.%s.%s", ruleID, key))
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "entry not found") || strings.Contains(lower, "not found") || strings.Contains(lower, "exit status 1") {
			return nil
		}
		return fmt.Errorf("delete %s failed: %w", key, err)
	}
	return nil
}

func setOrDeleteUCIOption(ruleID string, key string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return deleteUCIOption(ruleID, key)
	}
	return setUCIOption(ruleID, key, value)
}

func applyUCIListOption(ruleID string, key string, values []string) error {
	if err := deleteUCIOption(ruleID, key); err != nil {
		return err
	}
	for _, value := range values {
		_, err := runCommandCombined("uci", "-q", "add_list", fmt.Sprintf("homeproxy.%s.%s=%s", ruleID, key, value))
		if err != nil {
			return fmt.Errorf("set %s failed: %w", key, err)
		}
	}
	return nil
}

func commitHomeproxyConfig() error {
	_, err := runCommandCombined("uci", "-q", "commit", "homeproxy")
	if err != nil {
		return fmt.Errorf("uci commit failed: %w", err)
	}
	return nil
}

func deriveRuleClassNodeFromTag(value string) (string, string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", ""
	}
	lower := strings.ToLower(raw)
	switch lower {
	case "direct", "direct-out":
		return "direct", ""
	case "block", "block-out", "reject", "reject-out":
		return "block", ""
	}
	if strings.HasPrefix(raw, "cfg-") && strings.HasSuffix(raw, "-out") && len(raw) > len("cfg--out") {
		return "proxy", raw[len("cfg-") : len(raw)-len("-out")]
	}
	return "proxy", raw
}

func routingNodeIDSet(sections []uciSection) map[string]struct{} {
	out := make(map[string]struct{})
	for _, section := range sections {
		if section.Type != "routing_node" {
			continue
		}
		out[section.Name] = struct{}{}
	}
	return out
}

func resolveRuleOutboundUpdate(spec *rulesUpdateOutbound, sections []uciSection) (string, string, error) {
	if spec == nil {
		return "", "", fmt.Errorf("missing outbound patch")
	}
	class := strings.ToLower(strings.TrimSpace(spec.Class))
	node := strings.TrimSpace(spec.Node)
	if node == "" {
		node = strings.TrimSpace(spec.UCITag)
	}
	tag := strings.TrimSpace(spec.Tag)

	if class == "" && tag != "" {
		tagClass, tagNode := deriveRuleClassNodeFromTag(tag)
		class = tagClass
		if node == "" {
			node = tagNode
		}
	}
	if class == "" && node != "" {
		nodeClass, nodeID := deriveRuleClassNodeFromTag(node)
		if nodeClass != "" {
			class = nodeClass
		}
		if nodeID != "" {
			node = nodeID
		}
	}

	switch class {
	case "direct":
		return "route", "direct-out", nil
	case "block":
		return "reject", "", nil
	case "proxy":
	default:
		return "", "", fmt.Errorf("unsupported outbound.class: %q", spec.Class)
	}

	if node == "" {
		return "", "", fmt.Errorf("proxy outbound requires node")
	}
	proxyClass, proxyNode := deriveRuleClassNodeFromTag(node)
	if proxyClass == "direct" {
		return "route", "direct-out", nil
	}
	if proxyClass == "block" {
		return "reject", "", nil
	}
	if proxyNode != "" {
		node = proxyNode
	}

	nodes := routingNodeIDSet(sections)
	if _, ok := nodes[node]; !ok {
		return "", "", fmt.Errorf("routing node %q not found", node)
	}
	return "route", node, nil
}

func applyRuleOutboundUpdate(ruleID string, action string, outbound string) error {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "reject":
		if err := setUCIOption(ruleID, "action", "reject"); err != nil {
			return err
		}
		if err := deleteUCIOption(ruleID, "outbound"); err != nil {
			return err
		}
		return nil
	case "", "route", "route-options":
		if err := setUCIOption(ruleID, "action", "route"); err != nil {
			return err
		}
		outbound = strings.TrimSpace(outbound)
		if outbound == "" {
			outbound = "direct-out"
		}
		if err := setUCIOption(ruleID, "outbound", outbound); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported outbound action: %q", action)
	}
}

func applyRuleListPatchInUCI(ruleID string, cfg normalizedRuleConfig) error {
	managed := map[string]listPatch{
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
	for key, patch := range managed {
		if !patch.Set {
			continue
		}
		if err := applyUCIListOption(ruleID, key, patch.Values); err != nil {
			return err
		}
	}
	return nil
}

func resolveRuleNameUpdate(reqName *string, reqLabel *string) (string, bool) {
	if reqName != nil {
		return strings.TrimSpace(*reqName), true
	}
	if reqLabel != nil {
		return strings.TrimSpace(*reqLabel), true
	}
	return "", false
}

func createRoutingRuleSection(reqID string) (string, error) {
	ruleID := routingSectionFromAnyTag(reqID)
	ruleID = strings.TrimSpace(ruleID)
	if ruleID != "" {
		if strings.Contains(ruleID, " ") {
			return "", fmt.Errorf("invalid rule id")
		}
		if _, err := getUCISectionType(ruleID); err == nil {
			return "", fmt.Errorf("rule %q already exists", ruleID)
		}
		_, err := runCommandCombined("uci", "-q", "set", "homeproxy."+ruleID+"=routing_rule")
		if err != nil {
			return "", fmt.Errorf("create rule failed: %w", err)
		}
		return ruleID, nil
	}
	out, err := runCommandCombined("uci", "-q", "add", "homeproxy", "routing_rule")
	if err != nil {
		return "", fmt.Errorf("create rule failed: %w", err)
	}
	ruleID = strings.TrimSpace(out)
	if ruleID == "" {
		return "", fmt.Errorf("create rule failed: empty id")
	}
	return ruleID, nil
}

func parseDHCPLeases(path string) ([]deviceLeaseView, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []deviceLeaseView{}, nil
		}
		return nil, err
	}
	out := make([]deviceLeaseView, 0)
	now := time.Now().UTC()
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := strings.TrimSpace(fields[2])
		if ip == "" {
			continue
		}
		name := strings.TrimSpace(fields[3])
		if name == "" || name == "*" {
			name = ip
		}
		clientID := ""
		if len(fields) > 4 {
			clientID = strings.TrimSpace(fields[4])
		}
		expiresAtUnix, _ := strconv.ParseInt(fields[0], 10, 64)
		expiresAt := time.Time{}
		expired := false
		if expiresAtUnix > 0 {
			expiresAt = time.Unix(expiresAtUnix, 0).UTC()
			expired = expiresAt.Before(now)
		}
		out = append(out, deviceLeaseView{
			Name:          name,
			IP:            ip,
			MAC:           strings.TrimSpace(fields[1]),
			ClientID:      clientID,
			ExpiresAt:     expiresAt,
			ExpiresAtUnix: expiresAtUnix,
			Expired:       expired,
		})
	}
	return out, nil
}

func firstNonEmptyString(primary string, fallback string) string {
	primary = strings.TrimSpace(primary)
	if primary != "" {
		return primary
	}
	return strings.TrimSpace(fallback)
}

func boolToUCIValue(value bool) string {
	if value {
		return "1"
	}
	return "0"
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

	if err := ensureRoutingRuleSection(ruleID); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	changed := false
	if name, hasName := resolveRuleNameUpdate(req.Name, req.Label); hasName {
		if err := setOrDeleteUCIOption(ruleID, "label", name); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		changed = true
	}

	if req.Outbound != nil {
		sections, err := parseUCISections(homeproxyUCIConfigPath)
		if err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		action, outbound, err := resolveRuleOutboundUpdate(req.Outbound, sections)
		if err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := applyRuleOutboundUpdate(ruleID, action, outbound); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		changed = true
	}

	cfg := req.Config.normalize()
	if cfg.hasAny() {
		if err := applyRuleListPatchInUCI(ruleID, cfg); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		changed = true
	}

	if !changed {
		http.Error(w, "no changes provided", http.StatusBadRequest)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
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

func (s *matchService) handleRulesCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rulesCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ruleID, err := createRoutingRuleSection(firstNonEmptyString(req.ID, req.Tag))
	if err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := setUCIOption(ruleID, "enabled", boolToUCIValue(enabled)); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := setUCIOption(ruleID, "mode", "default"); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	name, hasName := resolveRuleNameUpdate(req.Name, req.Label)
	if !hasName {
		name = ruleID
	}
	if err := setOrDeleteUCIOption(ruleID, "label", name); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	outboundAction := "route"
	outboundValue := "direct-out"
	if req.Outbound != nil {
		sections, loadErr := parseUCISections(homeproxyUCIConfigPath)
		if loadErr != nil {
			http.Error(w, "create failed: "+loadErr.Error(), http.StatusInternalServerError)
			return
		}
		action, outbound, resolveErr := resolveRuleOutboundUpdate(req.Outbound, sections)
		if resolveErr != nil {
			http.Error(w, "create failed: "+resolveErr.Error(), http.StatusBadRequest)
			return
		}
		outboundAction = action
		outboundValue = outbound
	}
	if err := applyRuleOutboundUpdate(ruleID, outboundAction, outboundValue); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := req.Config.normalize()
	if cfg.hasAny() {
		if err := applyRuleListPatchInUCI(ruleID, cfg); err != nil {
			http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := rulesCreateResponse{
		Created:   true,
		ID:        ruleID,
		Tag:       routingRuleTag(ruleID),
		CreatedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rulesDeleteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ruleID := routingSectionFromAnyTag(firstNonEmptyString(req.ID, req.Tag))
	if ruleID == "" {
		http.Error(w, "missing rule tag/id", http.StatusBadRequest)
		return
	}
	if err := ensureRoutingRuleSection(ruleID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := runCommandCombined("uci", "-q", "delete", "homeproxy."+ruleID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := rulesDeleteResponse{
		Deleted:   true,
		ID:        ruleID,
		Tag:       routingRuleTag(ruleID),
		DeletedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRoutingNodesList(w http.ResponseWriter, r *http.Request) {
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

	nodes := make([]routingNodeView, 0)
	for _, section := range sections {
		if section.Type != "routing_node" {
			continue
		}
		name := strings.TrimSpace(section.Options["label"])
		if name == "" {
			name = section.Name
		}
		nodes = append(nodes, routingNodeView{
			ID:          section.Name,
			Name:        name,
			Enabled:     strings.TrimSpace(section.Options["enabled"]) != "0",
			Node:        strings.TrimSpace(section.Options["node"]),
			Tag:         "cfg-" + section.Name + "-out",
			OutboundTag: routingNodeOutboundTagFromSection(section),
		})
	}

	resp := routingNodesListResponse{
		ConfigPath: homeproxyUCIConfigPath,
		Nodes:      nodes,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRuleSetsList(w http.ResponseWriter, r *http.Request) {
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

	ruleSets := make([]ruleSetListItem, 0)
	for _, section := range sections {
		if section.Type != "ruleset" {
			continue
		}
		name := strings.TrimSpace(section.Options["label"])
		if name == "" {
			name = section.Name
		}
		ruleSets = append(ruleSets, ruleSetListItem{
			ID:             section.Name,
			Tag:            routingRuleTag(section.Name),
			Name:           name,
			Enabled:        strings.TrimSpace(section.Options["enabled"]) != "0",
			Type:           strings.TrimSpace(section.Options["type"]),
			Format:         strings.TrimSpace(section.Options["format"]),
			URL:            strings.TrimSpace(section.Options["url"]),
			Path:           strings.TrimSpace(section.Options["path"]),
			UpdateInterval: strings.TrimSpace(section.Options["update_interval"]),
			Outbound:       strings.TrimSpace(section.Options["outbound"]),
		})
	}

	resp := ruleSetsListResponse{
		ConfigPath: homeproxyUCIConfigPath,
		RuleSets:   ruleSets,
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	devices, err := parseDHCPLeases(homeproxyDHCPLeasesPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := devicesListResponse{
		LeasePath: homeproxyDHCPLeasesPath,
		Devices:   devices,
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
