package sopsencrypt_test

import (
	"strings"
	"testing"

	"terraform-provider-sops/internal/sopsencrypt"

	"gopkg.in/yaml.v3"
)

// sopsConfigDoc mirrors the .sops.yaml structure for test assertions.
type sopsConfigDoc struct {
	CreationRules []struct {
		PathRegex         string `yaml:"path_regex"`
		HCVaultTransitURI string `yaml:"hc_vault_transit_uri"`
	} `yaml:"creation_rules"`
}

func parseConfig(t *testing.T, content string) sopsConfigDoc {
	t.Helper()
	var doc sopsConfigDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("output is not valid YAML: %v\n---\n%s", err, content)
	}
	return doc
}

func TestGenerateSOPSConfig_NilRegexesProducesOneRule(t *testing.T) {
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://127.0.0.1:8200", "transit", "my-key", nil,
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	doc := parseConfig(t, content)

	if len(doc.CreationRules) != 1 {
		t.Fatalf("want 1 creation rule, got %d", len(doc.CreationRules))
	}
	if doc.CreationRules[0].PathRegex != "" {
		t.Errorf("want empty path_regex, got %q", doc.CreationRules[0].PathRegex)
	}
	if strings.Contains(content, "path_regex") {
		t.Errorf("path_regex key must not appear in output when pathRegexes is nil;\ngot:\n%s", content)
	}
}

func TestGenerateSOPSConfig_VaultURIFormat(t *testing.T) {
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://vault.example.com:8200", "transit", "app-key", nil,
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	doc := parseConfig(t, content)
	wantURI := "http://vault.example.com:8200/v1/transit/keys/app-key"

	if doc.CreationRules[0].HCVaultTransitURI != wantURI {
		t.Errorf("hc_vault_transit_uri = %q, want %q",
			doc.CreationRules[0].HCVaultTransitURI, wantURI)
	}
}

func TestGenerateSOPSConfig_TrailingSlashInAddress(t *testing.T) {
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://127.0.0.1:8200/", "transit", "my-key", nil,
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	doc := parseConfig(t, content)
	wantURI := "http://127.0.0.1:8200/v1/transit/keys/my-key"
	if uri := doc.CreationRules[0].HCVaultTransitURI; uri != wantURI {
		t.Errorf("URI = %q, want %q", uri, wantURI)
	}
}

func TestGenerateSOPSConfig_CustomPathRegexes(t *testing.T) {
	regexes := []string{`^secrets/.*\.yaml$`, `^config/.*\.json$`}
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://127.0.0.1:8200", "transit", "my-key", regexes,
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	doc := parseConfig(t, content)
	if len(doc.CreationRules) != 2 {
		t.Fatalf("want 2 creation rules, got %d", len(doc.CreationRules))
	}
	for i, want := range regexes {
		if doc.CreationRules[i].PathRegex != want {
			t.Errorf("rule[%d].path_regex = %q, want %q", i, doc.CreationRules[i].PathRegex, want)
		}
	}
}

func TestGenerateSOPSConfig_CustomTransitEngine(t *testing.T) {
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://127.0.0.1:8200", "secret-transit", "my-key", nil,
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	if !strings.Contains(content, "/v1/secret-transit/keys/my-key") {
		t.Errorf("expected custom engine path in URI; got:\n%s", content)
	}
}

func TestGenerateSOPSConfig_OutputIsValidYAML(t *testing.T) {
	content, err := sopsencrypt.GenerateSOPSConfig(
		"http://127.0.0.1:8200", "transit", "my-key",
		[]string{`\.ya?ml$`, `\.json$`, `^special:chars/.*$`},
	)
	if err != nil {
		t.Fatalf("GenerateSOPSConfig: %v", err)
	}

	var out interface{}
	if err := yaml.Unmarshal([]byte(content), &out); err != nil {
		t.Errorf("output is not valid YAML: %v\n---\n%s", err, content)
	}
}

func TestGenerateSOPSConfig_EmptyRegexListEqualsNil(t *testing.T) {
	withNil, err := sopsencrypt.GenerateSOPSConfig("http://127.0.0.1:8200", "transit", "k", nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	withEmpty, err := sopsencrypt.GenerateSOPSConfig("http://127.0.0.1:8200", "transit", "k", []string{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if withNil != withEmpty {
		t.Error("nil and empty pathRegexes should produce identical output")
	}
}
