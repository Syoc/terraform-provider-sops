package provider_test

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"terraform-provider-sops/internal/provider"
)

// testAccProtoV6ProviderFactories is used in every acceptance test step.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// requireEnv returns the value of the named environment variable, or skips the
// test if it is not set.
func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("environment variable %s not set", key)
	}
	return v
}

// envOrDefault returns the value of the named environment variable, falling
// back to fallback if it is not set.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
