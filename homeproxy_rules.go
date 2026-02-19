package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
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

var uciIdentifierRegex = regexp.MustCompile(`[^A-Za-z0-9_]+`)

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
	NodeName    string `json:"nodeName,omitempty"`
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

type nodeCreateRequest struct {
	Link      string `json:"link,omitempty"`
	Key       string `json:"key,omitempty"`
	Name      string `json:"name"`
	Outbound  string `json:"outbound,omitempty"`
	ID        string `json:"id,omitempty"`
	NodeID    string `json:"nodeId,omitempty"`
	RoutingID string `json:"routingId,omitempty"`
	NodeLabel string `json:"nodeLabel,omitempty"`
}

type nodeCreateResponse struct {
	Created         bool      `json:"created"`
	NodeID          string    `json:"nodeId"`
	NodeTag         string    `json:"nodeTag"`
	NodeName        string    `json:"nodeName"`
	RoutingID       string    `json:"routingId"`
	RoutingTag      string    `json:"routingTag"`
	RoutingName     string    `json:"routingName"`
	RoutingOutbound string    `json:"routingOutbound"`
	CreatedAt       time.Time `json:"createdAt"`
}

type nodeDeleteRequest struct {
	ID  string `json:"id,omitempty"`
	Tag string `json:"tag,omitempty"`
}

type nodeDeleteResponse struct {
	Deleted           bool      `json:"deleted"`
	NodeID            string    `json:"nodeId"`
	NodeTag           string    `json:"nodeTag"`
	RemovedRoutingIDs []string  `json:"removedRoutingIds"`
	UpdatedRules      int       `json:"updatedRules"`
	UpdatedRuleSets   int       `json:"updatedRuleSets"`
	DeletedAt         time.Time `json:"deletedAt"`
}

type nodeRenameRequest struct {
	ID   string `json:"id,omitempty"`
	Tag  string `json:"tag,omitempty"`
	Name string `json:"name"`
}

type nodeRenameResponse struct {
	Updated           bool      `json:"updated"`
	NodeID            string    `json:"nodeId"`
	NodeTag           string    `json:"nodeTag"`
	Name              string    `json:"name"`
	UpdatedRoutingIDs []string  `json:"updatedRoutingIds"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type ruleSetCreateRequest struct {
	ID                string `json:"id,omitempty"`
	Tag               string `json:"tag,omitempty"`
	Name              string `json:"name,omitempty"`
	Label             string `json:"label,omitempty"`
	Enabled           *bool  `json:"enabled,omitempty"`
	Format            string `json:"format,omitempty"`
	URL               string `json:"url"`
	Outbound          string `json:"outbound,omitempty"`
	UpdateInterval    string `json:"updateInterval,omitempty"`
	UpdateIntervalUCI string `json:"update_interval,omitempty"`
}

type ruleSetCreateResponse struct {
	Created   bool      `json:"created"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	CreatedAt time.Time `json:"createdAt"`
}

type ruleSetUpdateRequest struct {
	ID                string  `json:"id,omitempty"`
	Tag               string  `json:"tag,omitempty"`
	Name              *string `json:"name,omitempty"`
	Label             *string `json:"label,omitempty"`
	Enabled           *bool   `json:"enabled,omitempty"`
	Format            *string `json:"format,omitempty"`
	URL               *string `json:"url,omitempty"`
	Outbound          *string `json:"outbound,omitempty"`
	UpdateInterval    *string `json:"updateInterval,omitempty"`
	UpdateIntervalUCI *string `json:"update_interval,omitempty"`
}

type ruleSetUpdateResponse struct {
	Updated   bool      `json:"updated"`
	ID        string    `json:"id"`
	Tag       string    `json:"tag"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type ruleSetDeleteRequest struct {
	ID  string `json:"id,omitempty"`
	Tag string `json:"tag,omitempty"`
}

type ruleSetDeleteResponse struct {
	Deleted      bool      `json:"deleted"`
	ID           string    `json:"id"`
	Tag          string    `json:"tag"`
	UpdatedRules int       `json:"updatedRules"`
	DeletedAt    time.Time `json:"deletedAt"`
}

type parsedShareNode struct {
	Options map[string]interface{}
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

type subscriptionDefaults struct {
	AllowInsecure  bool
	PacketEncoding string
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func sanitizeUCIIdentifier(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = uciIdentifierRegex.ReplaceAllString(raw, "_")
	raw = strings.Trim(raw, "_")
	return raw
}

func decodeBase64Loose(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty base64 input")
	}
	value = strings.ReplaceAll(value, "-", "+")
	value = strings.ReplaceAll(value, "_", "/")
	switch len(value) % 4 {
	case 2:
		value += "=="
	case 3:
		value += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decodeShareComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

func compactStringValues(values []string, limit int) []string {
	if limit <= 0 {
		limit = 128
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func asString(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(typed, 'f', -1, 64))
	case bool:
		if typed {
			return "1"
		}
		return "0"
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func mapString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	return asString(m[key])
}

func splitCommaValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	return compactStringValues(parts, 64)
}

func setNodeOption(out map[string]interface{}, key string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	out[key] = value
}

func setNodeOptionList(out map[string]interface{}, key string, values []string) {
	values = compactStringValues(values, 64)
	if len(values) == 0 {
		return
	}
	out[key] = values
}

func parseShareLink(raw string) (*parsedShareNode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("share link is empty")
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "vmess://") {
		opts, err := parseVMessShareLink(raw)
		if err != nil {
			return nil, err
		}
		return finalizeParsedShareNode(opts)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid share link: %w", err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("missing share link scheme")
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	var opts map[string]interface{}
	switch scheme {
	case "anytls":
		opts, err = parseAnyTLSShareLink(u)
	case "http", "https":
		opts, err = parseHTTPShareLink(u, scheme)
	case "hysteria":
		opts, err = parseHysteriaShareLink(u)
	case "hysteria2", "hy2":
		opts, err = parseHysteria2ShareLink(u)
	case "socks", "socks4", "socks4a", "socsk5", "socks5h":
		opts, err = parseSocksShareLink(u, scheme)
	case "ss":
		opts, err = parseSSShareLink(raw)
	case "trojan":
		opts, err = parseTrojanShareLink(u)
	case "tuic":
		opts, err = parseTuicShareLink(u)
	case "vless":
		opts, err = parseVlessShareLink(u)
	default:
		return nil, fmt.Errorf("unsupported share link scheme: %s", scheme)
	}
	if err != nil {
		return nil, err
	}
	return finalizeParsedShareNode(opts)
}

func parseAnyTLSShareLink(u *url.URL) (map[string]interface{}, error) {
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nil, fmt.Errorf("anytls link missing password")
	}
	opts := map[string]interface{}{
		"type": "anytls",
		"tls":  "1",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	setNodeOption(opts, "password", decodeShareComponent(u.User.Username()))
	setNodeOption(opts, "tls_sni", u.Query().Get("sni"))
	if strings.EqualFold(u.Query().Get("insecure"), "1") {
		setNodeOption(opts, "tls_insecure", "1")
	} else {
		setNodeOption(opts, "tls_insecure", "0")
	}
	return opts, nil
}

func parseHTTPShareLink(u *url.URL, scheme string) (map[string]interface{}, error) {
	opts := map[string]interface{}{
		"type": "http",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	if u.User != nil {
		setNodeOption(opts, "username", decodeShareComponent(u.User.Username()))
		if password, ok := u.User.Password(); ok {
			setNodeOption(opts, "password", decodeShareComponent(password))
		}
	}
	if scheme == "https" {
		setNodeOption(opts, "tls", "1")
	} else {
		setNodeOption(opts, "tls", "0")
	}
	return opts, nil
}

func parseHysteriaShareLink(u *url.URL) (map[string]interface{}, error) {
	params := u.Query()
	protocol := firstNonEmptyValue(params.Get("protocol"), "udp")
	if protocol != "udp" {
		return nil, fmt.Errorf("unsupported hysteria protocol: %s", protocol)
	}
	opts := map[string]interface{}{
		"type":              "hysteria",
		"tls":               "1",
		"hysteria_protocol": protocol,
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	if auth := strings.TrimSpace(params.Get("auth")); auth != "" {
		setNodeOption(opts, "hysteria_auth_type", "string")
		setNodeOption(opts, "hysteria_auth_payload", auth)
	}
	setNodeOption(opts, "hysteria_obfs_password", params.Get("obfsParam"))
	setNodeOption(opts, "hysteria_down_mbps", params.Get("downmbps"))
	setNodeOption(opts, "hysteria_up_mbps", params.Get("upmbps"))
	setNodeOption(opts, "tls_sni", params.Get("peer"))
	setNodeOption(opts, "tls_alpn", params.Get("alpn"))
	if strings.EqualFold(params.Get("insecure"), "1") || strings.EqualFold(params.Get("insecure"), "true") {
		setNodeOption(opts, "tls_insecure", "1")
	} else {
		setNodeOption(opts, "tls_insecure", "0")
	}
	return opts, nil
}

func parseHysteria2ShareLink(u *url.URL) (map[string]interface{}, error) {
	params := u.Query()
	password := ""
	if u.User != nil {
		password = decodeShareComponent(u.User.Username())
		if pass, ok := u.User.Password(); ok && strings.TrimSpace(pass) != "" {
			password += ":" + decodeShareComponent(pass)
		}
	}
	opts := map[string]interface{}{
		"type": "hysteria2",
		"tls":  "1",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	setNodeOption(opts, "password", password)
	setNodeOption(opts, "hysteria_obfs_type", params.Get("obfs"))
	setNodeOption(opts, "hysteria_obfs_password", params.Get("obfs-password"))
	setNodeOption(opts, "tls_sni", params.Get("sni"))
	if strings.TrimSpace(params.Get("insecure")) != "" {
		setNodeOption(opts, "tls_insecure", "1")
	} else {
		setNodeOption(opts, "tls_insecure", "0")
	}
	return opts, nil
}

func parseSocksShareLink(u *url.URL, scheme string) (map[string]interface{}, error) {
	version := "5"
	if strings.Contains(scheme, "4") {
		version = "4"
	}
	opts := map[string]interface{}{
		"type":          "socks",
		"socks_version": version,
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	if u.User != nil {
		setNodeOption(opts, "username", decodeShareComponent(u.User.Username()))
		if pass, ok := u.User.Password(); ok {
			setNodeOption(opts, "password", decodeShareComponent(pass))
		}
	}
	return opts, nil
}

func parseSSShareLink(raw string) (map[string]interface{}, error) {
	link := strings.TrimSpace(raw)
	link = strings.TrimPrefix(link, "ss://")
	if link == "" {
		return nil, fmt.Errorf("invalid ss link")
	}

	label := ""
	if idx := strings.Index(link, "#"); idx >= 0 {
		label = decodeShareComponent(link[idx+1:])
		link = link[:idx]
	}

	parseURL := func(candidate string) (*url.URL, error) {
		return url.Parse("http://" + candidate)
	}
	u, err := parseURL(link)
	if err != nil {
		return nil, fmt.Errorf("invalid ss link: %w", err)
	}

	method := ""
	password := ""
	extractCreds := func(target *url.URL) {
		if target == nil || target.User == nil {
			return
		}
		user := strings.TrimSpace(target.User.Username())
		if user == "" {
			return
		}
		if pass, ok := target.User.Password(); ok {
			method = user
			password = decodeShareComponent(pass)
			return
		}
		decoded, decErr := decodeBase64Loose(decodeShareComponent(user))
		if decErr != nil {
			return
		}
		parts := strings.SplitN(decoded, ":", 2)
		if len(parts) != 2 {
			return
		}
		method = strings.TrimSpace(parts[0])
		password = parts[1]
	}
	extractCreds(u)

	if method == "" || password == "" || u.Hostname() == "" || u.Port() == "" {
		if decoded, decErr := decodeBase64Loose(link); decErr == nil {
			if alt, altErr := parseURL(decoded); altErr == nil {
				u = alt
				extractCreds(u)
			}
		}
	}
	if method == "" || password == "" {
		return nil, fmt.Errorf("invalid ss credentials")
	}

	pluginName := ""
	pluginOpts := ""
	if pluginRaw := strings.TrimSpace(u.Query().Get("plugin")); pluginRaw != "" {
		parts := strings.SplitN(pluginRaw, ";", 2)
		pluginName = strings.TrimSpace(parts[0])
		if pluginName == "simple-obfs" {
			pluginName = "obfs-local"
		}
		if len(parts) > 1 {
			pluginOpts = strings.TrimSpace(parts[1])
		}
	}

	opts := map[string]interface{}{
		"type":                       "shadowsocks",
		"label":                      label,
		"address":                    u.Hostname(),
		"port":                       firstNonEmptyValue(u.Port(), "80"),
		"shadowsocks_encrypt_method": method,
		"password":                   password,
	}
	setNodeOption(opts, "shadowsocks_plugin", pluginName)
	setNodeOption(opts, "shadowsocks_plugin_opts", pluginOpts)
	return opts, nil
}

func parseTrojanShareLink(u *url.URL) (map[string]interface{}, error) {
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nil, fmt.Errorf("trojan link missing password")
	}
	params := u.Query()
	opts := map[string]interface{}{
		"type": "trojan",
		"tls":  "1",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	setNodeOption(opts, "password", decodeShareComponent(u.User.Username()))
	setNodeOption(opts, "tls_sni", params.Get("sni"))
	if transport := strings.TrimSpace(params.Get("type")); transport != "" && transport != "tcp" {
		setNodeOption(opts, "transport", transport)
		switch transport {
		case "grpc":
			setNodeOption(opts, "grpc_servicename", params.Get("serviceName"))
		case "ws":
			setNodeOption(opts, "ws_host", decodeShareComponent(params.Get("host")))
			path := decodeShareComponent(params.Get("path"))
			if strings.Contains(path, "?ed=") {
				parts := strings.SplitN(path, "?ed=", 2)
				setNodeOption(opts, "websocket_early_data_header", "Sec-WebSocket-Protocol")
				setNodeOption(opts, "websocket_early_data", parts[1])
				path = parts[0]
			}
			setNodeOption(opts, "ws_path", path)
		}
	}
	return opts, nil
}

func parseTuicShareLink(u *url.URL) (map[string]interface{}, error) {
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nil, fmt.Errorf("tuic link missing uuid")
	}
	params := u.Query()
	opts := map[string]interface{}{
		"type": "tuic",
		"tls":  "1",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	setNodeOption(opts, "uuid", decodeShareComponent(u.User.Username()))
	if pass, ok := u.User.Password(); ok {
		setNodeOption(opts, "password", decodeShareComponent(pass))
	}
	setNodeOption(opts, "tuic_congestion_control", params.Get("congestion_control"))
	setNodeOption(opts, "tuic_udp_relay_mode", params.Get("udp_relay_mode"))
	setNodeOption(opts, "tls_sni", params.Get("sni"))
	setNodeOptionList(opts, "tls_alpn", splitCommaValues(decodeShareComponent(params.Get("alpn"))))
	return opts, nil
}

func parseVlessShareLink(u *url.URL) (map[string]interface{}, error) {
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nil, fmt.Errorf("vless link missing uuid")
	}
	params := u.Query()
	transport := strings.TrimSpace(params.Get("type"))
	if transport == "" {
		return nil, fmt.Errorf("vless link missing transport type")
	}
	if transport == "kcp" {
		return nil, fmt.Errorf("unsupported vless transport: kcp")
	}

	security := strings.TrimSpace(params.Get("security"))
	opts := map[string]interface{}{
		"type": "vless",
	}
	setNodeOption(opts, "label", decodeShareComponent(u.Fragment))
	setNodeOption(opts, "address", u.Hostname())
	setNodeOption(opts, "port", firstNonEmptyValue(u.Port(), "80"))
	setNodeOption(opts, "uuid", decodeShareComponent(u.User.Username()))
	if transport != "tcp" {
		setNodeOption(opts, "transport", transport)
	}
	if security == "tls" || security == "xtls" || security == "reality" {
		setNodeOption(opts, "tls", "1")
	} else {
		setNodeOption(opts, "tls", "0")
	}
	setNodeOption(opts, "tls_sni", params.Get("sni"))
	setNodeOptionList(opts, "tls_alpn", splitCommaValues(decodeShareComponent(params.Get("alpn"))))
	if security == "reality" {
		setNodeOption(opts, "tls_reality", "1")
		setNodeOption(opts, "tls_reality_public_key", decodeShareComponent(params.Get("pbk")))
		setNodeOption(opts, "tls_reality_short_id", params.Get("sid"))
	}
	if security == "tls" || security == "reality" {
		setNodeOption(opts, "vless_flow", params.Get("flow"))
	}
	setNodeOption(opts, "tls_utls", params.Get("fp"))

	switch transport {
	case "grpc":
		setNodeOption(opts, "grpc_servicename", params.Get("serviceName"))
	case "http", "tcp":
		if transport == "http" || strings.TrimSpace(params.Get("headerType")) == "http" {
			setNodeOptionList(opts, "http_host", splitCommaValues(decodeShareComponent(params.Get("host"))))
			setNodeOption(opts, "http_path", decodeShareComponent(params.Get("path")))
		}
	case "httpupgrade":
		setNodeOption(opts, "httpupgrade_host", decodeShareComponent(params.Get("host")))
		setNodeOption(opts, "http_path", decodeShareComponent(params.Get("path")))
	case "ws":
		setNodeOption(opts, "ws_host", decodeShareComponent(params.Get("host")))
		path := decodeShareComponent(params.Get("path"))
		if strings.Contains(path, "?ed=") {
			parts := strings.SplitN(path, "?ed=", 2)
			setNodeOption(opts, "websocket_early_data_header", "Sec-WebSocket-Protocol")
			setNodeOption(opts, "websocket_early_data", parts[1])
			path = parts[0]
		}
		setNodeOption(opts, "ws_path", path)
	}
	return opts, nil
}

func parseVMessShareLink(raw string) (map[string]interface{}, error) {
	payload := strings.TrimSpace(strings.TrimPrefix(raw, "vmess://"))
	if payload == "" {
		return nil, fmt.Errorf("invalid vmess link")
	}
	if strings.Contains(payload, "&") {
		return nil, fmt.Errorf("unsupported vmess format")
	}
	if idx := strings.Index(payload, "#"); idx >= 0 {
		payload = payload[:idx]
	}

	decoded, err := decodeBase64Loose(payload)
	if err != nil {
		return nil, fmt.Errorf("decode vmess failed: %w", err)
	}
	var vm map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &vm); err != nil {
		return nil, fmt.Errorf("parse vmess payload failed: %w", err)
	}
	if mapString(vm, "v") != "2" {
		return nil, fmt.Errorf("unsupported vmess version")
	}

	netMode := strings.TrimSpace(mapString(vm, "net"))
	if netMode == "kcp" {
		return nil, fmt.Errorf("unsupported vmess transport: kcp")
	}
	if netMode == "quic" && strings.TrimSpace(mapString(vm, "type")) != "" && strings.TrimSpace(mapString(vm, "type")) != "none" {
		return nil, fmt.Errorf("unsupported vmess quic mode")
	}

	opts := map[string]interface{}{
		"type": "vmess",
	}
	setNodeOption(opts, "label", decodeShareComponent(mapString(vm, "ps")))
	setNodeOption(opts, "address", mapString(vm, "add"))
	setNodeOption(opts, "port", mapString(vm, "port"))
	setNodeOption(opts, "uuid", mapString(vm, "id"))
	setNodeOption(opts, "vmess_alterid", mapString(vm, "aid"))
	setNodeOption(opts, "vmess_encrypt", firstNonEmptyValue(mapString(vm, "scy"), "auto"))
	if netMode != "" && netMode != "tcp" {
		setNodeOption(opts, "transport", netMode)
	}
	if strings.TrimSpace(mapString(vm, "tls")) == "tls" {
		setNodeOption(opts, "tls", "1")
	} else {
		setNodeOption(opts, "tls", "0")
	}
	setNodeOption(opts, "tls_sni", firstNonEmptyValue(mapString(vm, "sni"), mapString(vm, "host")))
	setNodeOptionList(opts, "tls_alpn", splitCommaValues(mapString(vm, "alpn")))
	setNodeOption(opts, "tls_utls", mapString(vm, "fp"))

	switch netMode {
	case "grpc":
		setNodeOption(opts, "grpc_servicename", mapString(vm, "path"))
	case "h2", "tcp":
		if netMode == "h2" || strings.TrimSpace(mapString(vm, "type")) == "http" {
			setNodeOption(opts, "transport", "http")
			setNodeOptionList(opts, "http_host", splitCommaValues(mapString(vm, "host")))
			setNodeOption(opts, "http_path", mapString(vm, "path"))
		}
	case "httpupgrade":
		setNodeOption(opts, "httpupgrade_host", mapString(vm, "host"))
		setNodeOption(opts, "http_path", mapString(vm, "path"))
	case "ws":
		setNodeOption(opts, "ws_host", mapString(vm, "host"))
		path := mapString(vm, "path")
		if strings.Contains(path, "?ed=") {
			parts := strings.SplitN(path, "?ed=", 2)
			setNodeOption(opts, "websocket_early_data_header", "Sec-WebSocket-Protocol")
			setNodeOption(opts, "websocket_early_data", parts[1])
			path = parts[0]
		}
		setNodeOption(opts, "ws_path", path)
	}

	return opts, nil
}

func finalizeParsedShareNode(opts map[string]interface{}) (*parsedShareNode, error) {
	if opts == nil {
		return nil, fmt.Errorf("empty parsed node")
	}
	address := strings.TrimSpace(asString(opts["address"]))
	port := strings.TrimSpace(asString(opts["port"]))
	address = strings.Trim(address, "[]")
	if err := validateNodeAddressAndPort(address, port); err != nil {
		return nil, err
	}
	opts["address"] = address
	opts["port"] = port

	label := strings.TrimSpace(asString(opts["label"]))
	if label == "" {
		if ip := net.ParseIP(address); ip != nil && strings.Contains(address, ":") {
			label = "[" + address + "]:" + port
		} else {
			label = address + ":" + port
		}
	}
	opts["label"] = label

	clean := make(map[string]interface{}, len(opts))
	for key, value := range opts {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			typed = strings.TrimSpace(typed)
			if typed == "" {
				continue
			}
			clean[key] = typed
		case []string:
			normalized := compactStringValues(typed, 128)
			if len(normalized) == 0 {
				continue
			}
			clean[key] = normalized
		default:
			text := strings.TrimSpace(asString(typed))
			if text == "" {
				continue
			}
			clean[key] = text
		}
	}
	return &parsedShareNode{Options: clean}, nil
}

func validateNodeAddressAndPort(address string, port string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("share link address is empty")
	}
	portInt, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || portInt <= 0 || portInt > 65535 {
		return fmt.Errorf("share link has invalid port: %q", port)
	}
	return nil
}

func sectionLabel(section uciSection) string {
	label := strings.TrimSpace(section.Options["label"])
	if label == "" {
		label = section.Name
	}
	return label
}

func sectionMapByName(sections []uciSection) map[string]uciSection {
	out := make(map[string]uciSection, len(sections))
	for _, section := range sections {
		out[section.Name] = section
	}
	return out
}

func findSectionByTypeAndName(sections []uciSection, sectionType string, name string) (uciSection, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return uciSection{}, false
	}
	for _, section := range sections {
		if section.Type == sectionType && section.Name == name {
			return section, true
		}
	}
	return uciSection{}, false
}

func findSectionByTypeAndLabel(sections []uciSection, sectionType string, label string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return "", errors.New("empty section label")
	}
	matches := make([]string, 0, 2)
	for _, section := range sections {
		if section.Type != sectionType {
			continue
		}
		if sectionLabel(section) == label {
			matches = append(matches, section.Name)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("section %q not found", label)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("section label %q is ambiguous", label)
	}
	return matches[0], nil
}

func routingNodeTagToID(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "cfg-") && strings.HasSuffix(value, "-out") && len(value) > len("cfg--out") {
		return strings.TrimSuffix(strings.TrimPrefix(value, "cfg-"), "-out")
	}
	return value
}

func resolveRoutingNodeIDRef(value string, sections []uciSection) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty routing node reference")
	}
	lower := strings.ToLower(value)
	switch lower {
	case "direct", "direct-out", "block", "block-out":
		return lower, nil
	}

	candidate := routingNodeTagToID(value)
	if section, ok := findSectionByTypeAndName(sections, "routing_node", candidate); ok {
		return section.Name, nil
	}
	if candidate != value {
		if _, ok := findSectionByTypeAndName(sections, "node", candidate); ok {
			return "", fmt.Errorf("outbound tag %q points to node section, not routing node", value)
		}
	}
	if sectionID, err := findSectionByTypeAndLabel(sections, "routing_node", value); err == nil {
		return sectionID, nil
	}
	return "", fmt.Errorf("routing node %q not found", value)
}

func resolveRoutingNodeOutboundOption(value string, sections []uciSection) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	switch strings.ToLower(value) {
	case "direct", "direct-out":
		return "", nil
	case "block", "block-out":
		return "block-out", nil
	}
	routingID, err := resolveRoutingNodeIDRef(value, sections)
	if err != nil {
		return "", err
	}
	switch routingID {
	case "direct", "direct-out":
		return "", nil
	case "block", "block-out":
		return "block-out", nil
	default:
		return routingID, nil
	}
}

func resolveRuleSetOutboundOption(value string, sections []uciSection) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	switch strings.ToLower(value) {
	case "direct", "direct-out":
		return "direct-out", nil
	case "block", "block-out":
		return "block-out", nil
	}
	routingID, err := resolveRoutingNodeIDRef(value, sections)
	if err != nil {
		return "", err
	}
	switch routingID {
	case "direct":
		return "direct-out", nil
	case "direct-out":
		return "direct-out", nil
	case "block", "block-out":
		return "block-out", nil
	default:
		return routingID, nil
	}
}

func resolveNodeIDRef(id string, tag string, sections []uciSection) (string, error) {
	raw := firstNonEmptyValue(id, tag)
	if raw == "" {
		return "", fmt.Errorf("missing node id/tag")
	}

	raw = routingNodeTagToID(raw)
	if section, ok := findSectionByTypeAndName(sections, "node", raw); ok {
		return section.Name, nil
	}
	if section, ok := findSectionByTypeAndName(sections, "routing_node", raw); ok {
		nodeID := strings.TrimSpace(section.Options["node"])
		if nodeID == "" || nodeID == "urltest" {
			return "", fmt.Errorf("routing node %q has no underlying node", section.Name)
		}
		if _, ok := findSectionByTypeAndName(sections, "node", nodeID); !ok {
			return "", fmt.Errorf("node %q not found", nodeID)
		}
		return nodeID, nil
	}

	if sectionID, err := findSectionByTypeAndLabel(sections, "node", firstNonEmptyValue(id, tag)); err == nil {
		return sectionID, nil
	}
	if routingID, err := findSectionByTypeAndLabel(sections, "routing_node", firstNonEmptyValue(id, tag)); err == nil {
		if routingSection, ok := findSectionByTypeAndName(sections, "routing_node", routingID); ok {
			nodeID := strings.TrimSpace(routingSection.Options["node"])
			if _, ok := findSectionByTypeAndName(sections, "node", nodeID); ok {
				return nodeID, nil
			}
		}
	}

	return "", fmt.Errorf("node %q not found", firstNonEmptyValue(id, tag))
}

func applyNodeOptions(sectionID string, options map[string]interface{}) error {
	for key, value := range options {
		switch typed := value.(type) {
		case string:
			if err := setOrDeleteUCIOption(sectionID, key, typed); err != nil {
				return err
			}
		case []string:
			if err := applyUCIListOption(sectionID, key, typed); err != nil {
				return err
			}
		default:
			asText := asString(typed)
			if err := setOrDeleteUCIOption(sectionID, key, asText); err != nil {
				return err
			}
		}
	}
	return nil
}

func allocateSectionID(preferred string, fallbackPrefix string) (string, error) {
	base := sanitizeUCIIdentifier(preferred)
	if base == "" {
		base = sanitizeUCIIdentifier(fallbackPrefix + "_" + md5Hex(strconv.FormatInt(time.Now().UnixNano(), 10))[:8])
	}
	if base == "" {
		base = fallbackPrefix + "_1"
	}

	candidate := base
	for i := 0; i < 2048; i++ {
		if _, err := getUCISectionType(candidate); err != nil {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s_%d", base, i+1)
	}
	return "", fmt.Errorf("failed to allocate free section id for %q", preferred)
}

func loadSubscriptionDefaults(sections []uciSection) subscriptionDefaults {
	out := subscriptionDefaults{
		AllowInsecure:  false,
		PacketEncoding: "",
	}
	for _, section := range sections {
		if !(section.Type == "homeproxy" && section.Name == "subscription") && section.Type != "subscription" {
			continue
		}
		out.AllowInsecure = strings.TrimSpace(section.Options["allow_insecure"]) == "1"
		out.PacketEncoding = strings.TrimSpace(section.Options["packet_encoding"])
		break
	}
	return out
}

func createNodeSection(nodeID string) error {
	if nodeID == "" {
		return fmt.Errorf("empty node id")
	}
	_, err := runCommandCombined("uci", "-q", "set", "homeproxy."+nodeID+"=node")
	if err != nil {
		return fmt.Errorf("create node failed: %w", err)
	}
	return nil
}

func createRoutingNodeSection(routingID string) error {
	if routingID == "" {
		return fmt.Errorf("empty routing node id")
	}
	_, err := runCommandCombined("uci", "-q", "set", "homeproxy."+routingID+"=routing_node")
	if err != nil {
		return fmt.Errorf("create routing node failed: %w", err)
	}
	return nil
}

func createRuleSetSection(reqID string) (string, error) {
	ruleSetID := routingSectionFromAnyTag(reqID)
	ruleSetID = strings.TrimSpace(ruleSetID)
	if ruleSetID != "" {
		if strings.Contains(ruleSetID, " ") {
			return "", fmt.Errorf("invalid ruleset id")
		}
		if _, err := getUCISectionType(ruleSetID); err == nil {
			return "", fmt.Errorf("ruleset %q already exists", ruleSetID)
		}
		_, err := runCommandCombined("uci", "-q", "set", "homeproxy."+ruleSetID+"=ruleset")
		if err != nil {
			return "", fmt.Errorf("create ruleset failed: %w", err)
		}
		return ruleSetID, nil
	}
	out, err := runCommandCombined("uci", "-q", "add", "homeproxy", "ruleset")
	if err != nil {
		return "", fmt.Errorf("create ruleset failed: %w", err)
	}
	ruleSetID = strings.TrimSpace(out)
	if ruleSetID == "" {
		return "", fmt.Errorf("create ruleset failed: empty id")
	}
	return ruleSetID, nil
}

func ensureRuleSetSection(ruleSetID string) error {
	sectionType, err := getUCISectionType(ruleSetID)
	if err != nil {
		return fmt.Errorf("ruleset %q not found: %w", ruleSetID, err)
	}
	if sectionType != "ruleset" {
		return fmt.Errorf("%q is not a ruleset section", ruleSetID)
	}
	return nil
}

func validateRuleSetURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("ruleset url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid ruleset url: %w", err)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return fmt.Errorf("invalid ruleset url hostname")
	}
	return nil
}

func validateRuleSetFormat(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "binary"
	}
	switch value {
	case "binary", "source":
		return value, nil
	default:
		return "", fmt.Errorf("unsupported ruleset format: %q", value)
	}
}

func removeSetFromList(values []string, toRemove map[string]struct{}) ([]string, bool) {
	if len(values) == 0 || len(toRemove) == 0 {
		return values, false
	}
	out := make([]string, 0, len(values))
	changed := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := toRemove[value]; ok {
			changed = true
			continue
		}
		out = append(out, value)
	}
	return compactStringValues(out, 1024), changed
}

func removeRuleSetReferences(ruleSetID string, sections []uciSection) (int, error) {
	remove := map[string]struct{}{ruleSetID: {}}
	updated := 0
	for _, section := range sections {
		if section.Type != "routing_rule" && section.Type != "dns_rule" {
			continue
		}
		current := sectionListValue(section, "rule_set")
		next, changed := removeSetFromList(current, remove)
		if !changed {
			continue
		}
		if err := applyUCIListOption(section.Name, "rule_set", next); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
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

	nodeLabels := make(map[string]string)
	for _, section := range sections {
		if section.Type != "node" {
			continue
		}
		nodeLabels[section.Name] = sectionLabel(section)
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
		nodeID := strings.TrimSpace(section.Options["node"])
		nodeName := strings.TrimSpace(nodeLabels[nodeID])
		if nodeName == "" && nodeID != "" {
			nodeName = nodeID
		}
		nodes = append(nodes, routingNodeView{
			ID:          section.Name,
			Name:        name,
			Enabled:     strings.TrimSpace(section.Options["enabled"]) != "0",
			Node:        nodeID,
			NodeName:    nodeName,
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

func (s *matchService) handleNodesCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req nodeCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	link := firstNonEmptyValue(req.Link, req.Key)
	if link == "" {
		http.Error(w, "missing share link", http.StatusBadRequest)
		return
	}
	routingName := strings.TrimSpace(req.Name)
	if routingName == "" {
		http.Error(w, "missing routing node name", http.StatusBadRequest)
		return
	}

	parsed, err := parseShareLink(link)
	if err != nil {
		http.Error(w, "parse link failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	subscription := loadSubscriptionDefaults(sections)

	nodeOptions := make(map[string]interface{}, len(parsed.Options)+2)
	for key, value := range parsed.Options {
		nodeOptions[key] = value
	}
	nodeLabel := firstNonEmptyValue(req.NodeLabel, asString(nodeOptions["label"]))
	if nodeLabel == "" {
		nodeLabel = routingName
	}
	nodeOptions["label"] = nodeLabel

	nodeType := strings.ToLower(strings.TrimSpace(asString(nodeOptions["type"])))
	if subscription.AllowInsecure && strings.TrimSpace(asString(nodeOptions["tls"])) == "1" && strings.TrimSpace(asString(nodeOptions["tls_insecure"])) == "" {
		nodeOptions["tls_insecure"] = "1"
	}
	if (nodeType == "vless" || nodeType == "vmess") && strings.TrimSpace(asString(nodeOptions["packet_encoding"])) == "" {
		nodeOptions["packet_encoding"] = firstNonEmptyValue(subscription.PacketEncoding, "xudp")
	}

	preferredNodeID := firstNonEmptyValue(req.NodeID, req.ID)
	if preferredNodeID == "" {
		preferredNodeID = md5Hex(nodeLabel)
	}
	nodeID, err := allocateSectionID(preferredNodeID, "node")
	if err != nil {
		http.Error(w, "create node failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := createNodeSection(nodeID); err != nil {
		http.Error(w, "create node failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := applyNodeOptions(nodeID, nodeOptions); err != nil {
		http.Error(w, "create node failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	preferredRoutingID := firstNonEmptyValue(req.RoutingID, sanitizeUCIIdentifier(routingName))
	routingID, err := allocateSectionID(preferredRoutingID, "routing_node")
	if err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := createRoutingNodeSection(routingID); err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setUCIOption(routingID, "label", routingName); err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := setUCIOption(routingID, "enabled", "1"); err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := setUCIOption(routingID, "node", nodeID); err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	routingOutbound, err := resolveRoutingNodeOutboundOption(req.Outbound, sections)
	if err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := setOrDeleteUCIOption(routingID, "outbound", routingOutbound); err != nil {
		http.Error(w, "create routing node failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "create node failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := nodeCreateResponse{
		Created:         true,
		NodeID:          nodeID,
		NodeTag:         "cfg-" + nodeID + "-out",
		NodeName:        nodeLabel,
		RoutingID:       routingID,
		RoutingTag:      "cfg-" + routingID + "-out",
		RoutingName:     routingName,
		RoutingOutbound: firstNonEmptyValue(routingOutbound, "direct"),
		CreatedAt:       time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleNodesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req nodeDeleteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nodeID, err := resolveNodeIDRef(req.ID, req.Tag, sections)
	if err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	removedRoutingIDs := make([]string, 0)
	removedRoutingSet := make(map[string]struct{})
	for _, section := range sections {
		if section.Type != "routing_node" {
			continue
		}
		if strings.TrimSpace(section.Options["node"]) != nodeID {
			continue
		}
		removedRoutingIDs = append(removedRoutingIDs, section.Name)
		removedRoutingSet[section.Name] = struct{}{}
	}

	updatedRules := 0
	updatedRuleSets := 0
	for _, section := range sections {
		switch section.Type {
		case "routing_node":
			if _, removed := removedRoutingSet[section.Name]; removed {
				continue
			}
			outbound := strings.TrimSpace(section.Options["outbound"])
			if outbound == "" {
				continue
			}
			if _, removed := removedRoutingSet[outbound]; removed {
				if err := deleteUCIOption(section.Name, "outbound"); err != nil {
					http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
		case "routing_rule":
			outbound := strings.TrimSpace(section.Options["outbound"])
			if _, removed := removedRoutingSet[outbound]; !removed {
				continue
			}
			action := strings.TrimSpace(section.Options["action"])
			if action == "reject" {
				if err := deleteUCIOption(section.Name, "outbound"); err != nil {
					http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				if err := setUCIOption(section.Name, "action", "route"); err != nil {
					http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if err := setUCIOption(section.Name, "outbound", "direct-out"); err != nil {
					http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
			updatedRules++
		case "ruleset":
			outbound := strings.TrimSpace(section.Options["outbound"])
			if _, removed := removedRoutingSet[outbound]; !removed {
				continue
			}
			if err := deleteUCIOption(section.Name, "outbound"); err != nil {
				http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			updatedRuleSets++
		}
	}

	for _, routingID := range removedRoutingIDs {
		if _, err := runCommandCombined("uci", "-q", "delete", "homeproxy."+routingID); err != nil {
			http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := deleteUCIOption("config", "main_node"); err == nil {
		_ = deleteUCIOption("config", "main_udp_node")
	}
	if _, err := runCommandCombined("uci", "-q", "delete", "homeproxy."+nodeID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := nodeDeleteResponse{
		Deleted:           true,
		NodeID:            nodeID,
		NodeTag:           "cfg-" + nodeID + "-out",
		RemovedRoutingIDs: removedRoutingIDs,
		UpdatedRules:      updatedRules,
		UpdatedRuleSets:   updatedRuleSets,
		DeletedAt:         time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleNodesRename(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req nodeRenameRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	newName := strings.TrimSpace(req.Name)
	if newName == "" {
		http.Error(w, "missing new name", http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nodeID, err := resolveNodeIDRef(req.ID, req.Tag, sections)
	if err != nil {
		http.Error(w, "rename failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, ok := findSectionByTypeAndName(sections, "node", nodeID); !ok {
		http.Error(w, "rename failed: node not found", http.StatusBadRequest)
		return
	}

	if err := setUCIOption(nodeID, "label", newName); err != nil {
		http.Error(w, "rename failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	updatedRouting := make([]string, 0)
	for _, section := range sections {
		if section.Type != "routing_node" {
			continue
		}
		if strings.TrimSpace(section.Options["node"]) != nodeID {
			continue
		}
		if err := setUCIOption(section.Name, "label", newName); err != nil {
			http.Error(w, "rename failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		updatedRouting = append(updatedRouting, section.Name)
	}

	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "rename failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := nodeRenameResponse{
		Updated:           true,
		NodeID:            nodeID,
		NodeTag:           "cfg-" + nodeID + "-out",
		Name:              newName,
		UpdatedRoutingIDs: updatedRouting,
		UpdatedAt:         time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRuleSetsCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ruleSetCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	name := firstNonEmptyValue(req.Name, req.Label)
	if strings.TrimSpace(name) == "" {
		http.Error(w, "missing ruleset name", http.StatusBadRequest)
		return
	}
	if err := validateRuleSetURL(req.URL); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	format, err := validateRuleSetFormat(req.Format)
	if err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	outbound, err := resolveRuleSetOutboundOption(req.Outbound, sections)
	if err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	rulesetIDSeed := firstNonEmptyValue(req.ID, req.Tag, sanitizeUCIIdentifier(name))
	ruleSetID, err := createRuleSetSection(rulesetIDSeed)
	if err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	updateInterval := firstNonEmptyValue(req.UpdateInterval, req.UpdateIntervalUCI, "1d")
	if err := setUCIOption(ruleSetID, "label", name); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setUCIOption(ruleSetID, "enabled", boolToUCIValue(enabled)); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setUCIOption(ruleSetID, "type", "remote"); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setUCIOption(ruleSetID, "format", format); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setUCIOption(ruleSetID, "url", strings.TrimSpace(req.URL)); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setOrDeleteUCIOption(ruleSetID, "outbound", outbound); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := setOrDeleteUCIOption(ruleSetID, "update_interval", updateInterval); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := ruleSetCreateResponse{
		Created:   true,
		ID:        ruleSetID,
		Tag:       routingRuleTag(ruleSetID),
		CreatedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRuleSetsUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ruleSetUpdateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ruleSetID := routingSectionFromAnyTag(firstNonEmptyValue(req.ID, req.Tag))
	if ruleSetID == "" {
		http.Error(w, "missing ruleset id/tag", http.StatusBadRequest)
		return
	}
	if err := ensureRuleSetSection(ruleSetID); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	changed := false
	if req.Name != nil || req.Label != nil {
		name := ""
		if req.Name != nil {
			name = strings.TrimSpace(*req.Name)
		} else if req.Label != nil {
			name = strings.TrimSpace(*req.Label)
		}
		if err := setOrDeleteUCIOption(ruleSetID, "label", name); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}
	if req.Enabled != nil {
		if err := setUCIOption(ruleSetID, "enabled", boolToUCIValue(*req.Enabled)); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}
	if req.Format != nil {
		format, formatErr := validateRuleSetFormat(*req.Format)
		if formatErr != nil {
			http.Error(w, "update failed: "+formatErr.Error(), http.StatusBadRequest)
			return
		}
		if err := setUCIOption(ruleSetID, "format", format); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}
	if req.URL != nil {
		if err := validateRuleSetURL(*req.URL); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := setUCIOption(ruleSetID, "url", strings.TrimSpace(*req.URL)); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}
	if req.Outbound != nil {
		outbound, outboundErr := resolveRuleSetOutboundOption(*req.Outbound, sections)
		if outboundErr != nil {
			http.Error(w, "update failed: "+outboundErr.Error(), http.StatusBadRequest)
			return
		}
		if err := setOrDeleteUCIOption(ruleSetID, "outbound", outbound); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}
	updateIntervalPatch := req.UpdateInterval
	if updateIntervalPatch == nil {
		updateIntervalPatch = req.UpdateIntervalUCI
	}
	if updateIntervalPatch != nil {
		if err := setOrDeleteUCIOption(ruleSetID, "update_interval", strings.TrimSpace(*updateIntervalPatch)); err != nil {
			http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		changed = true
	}

	if !changed {
		http.Error(w, "no changes provided", http.StatusBadRequest)
		return
	}
	if err := setUCIOption(ruleSetID, "type", "remote"); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := ruleSetUpdateResponse{
		Updated:   true,
		ID:        ruleSetID,
		Tag:       routingRuleTag(ruleSetID),
		UpdatedAt: time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (s *matchService) handleRuleSetsDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ruleSetDeleteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ruleSetID := routingSectionFromAnyTag(firstNonEmptyValue(req.ID, req.Tag))
	if ruleSetID == "" {
		http.Error(w, "missing ruleset id/tag", http.StatusBadRequest)
		return
	}
	if err := ensureRuleSetSection(ruleSetID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	sections, err := parseUCISections(homeproxyUCIConfigPath)
	if err != nil {
		http.Error(w, "load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updatedRules, err := removeRuleSetReferences(ruleSetID, sections)
	if err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := runCommandCombined("uci", "-q", "delete", "homeproxy."+ruleSetID); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := commitHomeproxyConfig(); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := ruleSetDeleteResponse{
		Deleted:      true,
		ID:           ruleSetID,
		Tag:          routingRuleTag(ruleSetID),
		UpdatedRules: updatedRules,
		DeletedAt:    time.Now(),
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

	// Some OpenWrt init scripts return non-zero even when the target state was reached.
	if running, _, statusErr := queryHomeproxyStatus(); statusErr == nil {
		switch action {
		case "stop":
			if !running {
				return nil
			}
		case "start", "restart":
			if running {
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
