package main

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"
)

func mustCompileHeadlessRule(t *testing.T, opts option.DefaultHeadlessRule) adapter.HeadlessRule {
	t.Helper()
	compiled, err := rule.NewHeadlessRule(context.Background(), option.HeadlessRule{
		DefaultOptions: opts,
	})
	if err != nil {
		t.Fatalf("compile headless rule: %v", err)
	}
	return compiled
}

func TestMatchAnyResetsRuleCacheBetweenRuleSets_DomainRules(t *testing.T) {
	matchingSet := []adapter.HeadlessRule{
		mustCompileHeadlessRule(t, option.DefaultHeadlessRule{
			DomainSuffix: badoption.Listable[string]{"google.com"},
		}),
	}
	nonMatchingSet := []adapter.HeadlessRule{
		mustCompileHeadlessRule(t, option.DefaultHeadlessRule{
			DomainSuffix: badoption.Listable[string]{"example.com"},
		}),
	}

	meta := buildMetadata("gemini.google.com")

	if !matchAny(matchingSet, &meta) {
		t.Fatalf("expected first ruleset to match")
	}
	if matchAny(nonMatchingSet, &meta) {
		t.Fatalf("expected second ruleset not to match, but got false positive")
	}
}

func TestMatchAnyResetsRuleCacheBetweenRuleSets_MixedDomainAndCIDR(t *testing.T) {
	domainSet := []adapter.HeadlessRule{
		mustCompileHeadlessRule(t, option.DefaultHeadlessRule{
			DomainSuffix: badoption.Listable[string]{"google.com"},
		}),
	}
	ipSet := []adapter.HeadlessRule{
		mustCompileHeadlessRule(t, option.DefaultHeadlessRule{
			IPCIDR: badoption.Listable[string]{"203.0.113.0/24"},
		}),
	}

	meta := buildMetadata("gemini.google.com")

	if !matchAny(domainSet, &meta) {
		t.Fatalf("expected first ruleset to match")
	}
	if matchAny(ipSet, &meta) {
		t.Fatalf("expected CIDR ruleset not to match domain input, but got false positive")
	}
}
