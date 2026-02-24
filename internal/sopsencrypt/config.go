package sopsencrypt

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// sopsFileConfig is the Go representation of a .sops.yaml file.
type sopsFileConfig struct {
	CreationRules []sopsCreationRule `yaml:"creation_rules"`
}

type sopsCreationRule struct {
	PathRegex         string `yaml:"path_regex,omitempty"`
	HCVaultTransitURI string `yaml:"hc_vault_transit_uri"`
}

// GenerateSOPSConfig renders a .sops.yaml configuration file that instructs
// the SOPS CLI to use the given Vault Transit key.
//
// If pathRegexes is empty or nil, a single catch-all creation_rule is emitted
// with no path_regex, which matches all files — the standard SOPS default
// behaviour when no path filter is specified.
//
// If pathRegexes is non-empty, one creation_rule is emitted per regex.
//
// The vault URI for each rule is constructed as:
//
//	<vaultAddress>/v1/<transitPath>/keys/<keyName>
func GenerateSOPSConfig(vaultAddress, transitPath, keyName string, pathRegexes []string) (string, error) {
	uri := strings.TrimRight(vaultAddress, "/") + "/v1/" + transitPath + "/keys/" + keyName

	var rules []sopsCreationRule
	if len(pathRegexes) == 0 {
		rules = []sopsCreationRule{{HCVaultTransitURI: uri}}
	} else {
		rules = make([]sopsCreationRule, len(pathRegexes))
		for i, re := range pathRegexes {
			rules[i] = sopsCreationRule{
				PathRegex:         re,
				HCVaultTransitURI: uri,
			}
		}
	}

	cfg := sopsFileConfig{CreationRules: rules}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return "", fmt.Errorf("marshaling sops config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("closing yaml encoder: %w", err)
	}

	return buf.String(), nil
}
