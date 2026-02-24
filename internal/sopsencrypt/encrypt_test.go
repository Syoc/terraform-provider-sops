package sopsencrypt_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"terraform-provider-sops/internal/sopsencrypt"
)

// mockVaultServer simulates the Vault Transit encrypt endpoint.
// The "encrypted" payload is vault:v1:<base64(plaintext)> so tests can
// verify round-trips without a real Vault instance.
func mockVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if strings.Contains(r.URL.Path, "/encrypt/") {
			var req struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"data": map[string]interface{}{
					"ciphertext": "vault:v1:" + req.Plaintext,
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
}

func newTestClient(t *testing.T, srv *httptest.Server) *vaultapi.Client {
	t.Helper()
	c, err := sopsencrypt.NewVaultClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}
	return c
}

// ── EncryptToJSON ──────────────────────────────────────────────────────────

func TestEncryptToJSON_ReturnsSOPSJSON(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key",
		`{"password":"secret","host":"db.example.com"}`,
		sopsencrypt.EncryptOpts{},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, result)
	}
	if _, ok := doc["sops"]; !ok {
		t.Error("result missing top-level 'sops' key")
	}
	for _, key := range []string{"password", "host"} {
		v, ok := doc[key].(string)
		if !ok || !strings.HasPrefix(v, "ENC[") {
			t.Errorf("key %q not encrypted: %v", key, doc[key])
		}
	}
}

func TestEncryptToJSON_NestedStructure(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	content := `{"database":{"host":"db.example.com","password":"secret"},"api_key":"mykey"}`
	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key", content, sopsencrypt.EncryptOpts{},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	db, ok := doc["database"].(map[string]interface{})
	if !ok {
		t.Fatal("nested 'database' key missing or wrong type")
	}
	for _, k := range []string{"host", "password"} {
		v, _ := db[k].(string)
		if !strings.HasPrefix(v, "ENC[") {
			t.Errorf("database.%s not encrypted: %v", k, db[k])
		}
	}
}

func TestEncryptToJSON_PrettyOutput(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key",
		`{"key":"value"}`,
		sopsencrypt.EncryptOpts{PrettyJSON: true},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	if !strings.Contains(result, "\n") {
		t.Error("pretty output expected newlines; got compact JSON")
	}
	// Must still be valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		t.Fatalf("pretty result is not valid JSON: %v", err)
	}
}

func TestEncryptToJSON_CompactByDefault(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key",
		`{"key":"value"}`,
		sopsencrypt.EncryptOpts{PrettyJSON: false},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	// Compact output: no leading whitespace on lines.
	for _, line := range strings.Split(result, "\n") {
		if strings.HasPrefix(line, "  ") {
			t.Errorf("compact output should not have indented lines; got: %q", line)
		}
	}
}

func TestEncryptToJSON_EncryptedRegexOnlyEncryptsMatchingKeys(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key",
		`{"password":"secret","host":"db.example.com"}`,
		sopsencrypt.EncryptOpts{EncryptedRegex: "^password$"},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal([]byte(result), &doc) //nolint:errcheck

	pw, _ := doc["password"].(string)
	if !strings.HasPrefix(pw, "ENC[") {
		t.Errorf("'password' should be encrypted: %v", pw)
	}
	host, _ := doc["host"].(string)
	if strings.HasPrefix(host, "ENC[") {
		t.Errorf("'host' should NOT be encrypted (not matching regex): %v", host)
	}
}

func TestEncryptToJSON_SamePlaintextProducesDifferentCiphertexts(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	content := `{"key":"value"}`
	opts := sopsencrypt.EncryptOpts{}
	r1, _ := sopsencrypt.EncryptToJSON(newTestClient(t, srv), "transit", "k", content, opts)
	r2, _ := sopsencrypt.EncryptToJSON(newTestClient(t, srv), "transit", "k", content, opts)
	if r1 == r2 {
		t.Error("SOPS should produce different ciphertext on each call (random nonce)")
	}
}

// ── EncryptToYAML ──────────────────────────────────────────────────────────

func TestEncryptToYAML_ReturnsSOPSYAML(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToYAML(
		newTestClient(t, srv), "transit", "test-key",
		`{"password":"secret","host":"db.example.com"}`,
		sopsencrypt.EncryptOpts{},
	)
	if err != nil {
		t.Fatalf("EncryptToYAML: %v", err)
	}

	// Output must not be JSON.
	if strings.HasPrefix(strings.TrimSpace(result), "{") {
		t.Error("YAML output should not start with '{'")
	}
	// Must contain SOPS metadata block.
	if !strings.Contains(result, "sops:") {
		t.Error("YAML output missing 'sops:' metadata block")
	}
	// Values must be encrypted.
	if !strings.Contains(result, "ENC[") {
		t.Error("YAML output missing ENC[] values")
	}
}

func TestEncryptToYAML_NestedStructure(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	content := `{"database":{"host":"db.example.com","password":"secret"}}`
	result, err := sopsencrypt.EncryptToYAML(
		newTestClient(t, srv), "transit", "test-key", content, sopsencrypt.EncryptOpts{},
	)
	if err != nil {
		t.Fatalf("EncryptToYAML: %v", err)
	}
	// Nested key should appear in YAML format.
	if !strings.Contains(result, "database:") {
		t.Error("YAML output missing nested 'database' key")
	}
	if !strings.Contains(result, "ENC[") {
		t.Error("YAML output missing ENC[] values")
	}
}

// ── NewVaultClient ─────────────────────────────────────────────────────────

func TestNewVaultClient_SetsAddressAndToken(t *testing.T) {
	var gotToken, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"data": map[string]interface{}{
				"ciphertext": "vault:v1:dGVzdA==",
			},
		})
	}))
	defer srv.Close()

	client, err := sopsencrypt.NewVaultClient(srv.URL, "s.supersecret")
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}
	sopsencrypt.EncryptToJSON(client, "transit", "k", `{"x":"y"}`, sopsencrypt.EncryptOpts{}) //nolint:errcheck

	if gotToken != "s.supersecret" {
		t.Errorf("X-Vault-Token = %q, want %q", gotToken, "s.supersecret")
	}
	if !strings.Contains(gotPath, "/v1/transit/encrypt/k") {
		t.Errorf("request path = %q, expected to contain /v1/transit/encrypt/k", gotPath)
	}
}

func TestNewVaultClient_EncodedKeyInVaultRequest(t *testing.T) {
	srv := mockVaultServer(t)
	defer srv.Close()

	result, err := sopsencrypt.EncryptToJSON(
		newTestClient(t, srv), "transit", "test-key",
		`{"secret":"value"}`,
		sopsencrypt.EncryptOpts{},
	)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	var doc map[string]interface{}
	json.Unmarshal([]byte(result), &doc) //nolint:errcheck

	sopsBlock := doc["sops"].(map[string]interface{})
	vaultKeys := sopsBlock["hc_vault"].([]interface{})
	firstKey := vaultKeys[0].(map[string]interface{})

	enc := firstKey["enc"].(string)
	payload := strings.TrimPrefix(enc, "vault:v1:")
	if _, err := base64.StdEncoding.DecodeString(payload); err != nil {
		t.Errorf("enc payload is not valid base64: %v", err)
	}
}
