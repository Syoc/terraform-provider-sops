// Package sopsencrypt wraps SOPS encryption primitives with HashiCorp Vault
// Transit as the key backend. The vault client is injected explicitly so that
// no environment variables are read or written by this package.
package sopsencrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/hcvault"
	sopsjson "github.com/getsops/sops/v3/stores/json"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	sopsversion "github.com/getsops/sops/v3/version"
	vaultapi "github.com/hashicorp/vault/api"
)

// EncryptOpts controls which keys are encrypted and optional output formatting.
//
// At most one scope field should be non-empty; they mirror the SOPS CLI flags:
//
//	UnencryptedSuffix – keys ending with this suffix are left in plaintext
//	EncryptedSuffix   – only keys ending with this suffix are encrypted
//	UnencryptedRegex  – keys matching this regex are left in plaintext
//	EncryptedRegex    – only keys matching this regex are encrypted
//
// If all scope fields are empty, every key is encrypted (SOPS default).
//
// PrettyJSON is only respected by EncryptToJSON.
type EncryptOpts struct {
	UnencryptedSuffix string
	EncryptedSuffix   string
	UnencryptedRegex  string
	EncryptedRegex    string
	PrettyJSON        bool
}

// EncryptToJSON parses jsonContent (a JSON document, typically produced by
// jsonencode()), encrypts it with Vault Transit, and returns a
// SOPS-encrypted JSON document. The ciphertext is decryptable with
// `sops -d --input-type json`.
//
// If opts.PrettyJSON is true the output is indented with two spaces.
func EncryptToJSON(client *vaultapi.Client, transitPath, keyName, jsonContent string, opts EncryptOpts) (string, error) {
	out, err := encryptDocument(client, transitPath, keyName, jsonContent, opts,
		func(tree sops.Tree) ([]byte, error) {
			return (&sopsjson.Store{}).EmitEncryptedFile(tree)
		})
	if err != nil {
		return "", err
	}
	if opts.PrettyJSON {
		var buf bytes.Buffer
		if err := json.Indent(&buf, out, "", "  "); err != nil {
			return "", fmt.Errorf("pretty-printing JSON: %w", err)
		}
		return buf.String(), nil
	}
	return string(out), nil
}

// EncryptToYAML parses jsonContent, encrypts it with Vault Transit, and
// returns a SOPS-encrypted YAML 1.2 document. The ciphertext is decryptable
// with `sops -d --input-type yaml`.
//
// Input is always JSON (jsonencode() output); the YAML serialisation is
// handled internally.
func EncryptToYAML(client *vaultapi.Client, transitPath, keyName, jsonContent string, opts EncryptOpts) (string, error) {
	out, err := encryptDocument(client, transitPath, keyName, jsonContent, opts,
		func(tree sops.Tree) ([]byte, error) {
			return (&sopsyaml.Store{}).EmitEncryptedFile(tree)
		})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// encryptDocument is the shared implementation. jsonContent is parsed with
// the JSON store (format-agnostic input), encrypted, then serialised by
// emit into the target format.
func encryptDocument(
	client *vaultapi.Client,
	transitPath, keyName, jsonContent string,
	opts EncryptOpts,
	emit func(sops.Tree) ([]byte, error),
) ([]byte, error) {
	branches, err := (&sopsjson.Store{}).LoadPlainFile([]byte(jsonContent))
	if err != nil {
		return nil, fmt.Errorf("parsing content as JSON: %w", err)
	}

	dataKey, err := generateDataKey()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := wrapDataKey(client, transitPath, keyName, dataKey)
	if err != nil {
		return nil, err
	}

	masterKey := &hcvault.MasterKey{
		VaultAddress: client.Address(),
		EnginePath:   transitPath,
		KeyName:      keyName,
		EncryptedKey: encryptedKey,
		CreationDate: time.Now().UTC(),
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         []sops.KeyGroup{{masterKey}},
			Version:           sopsversion.Version,
			UnencryptedSuffix: opts.UnencryptedSuffix,
			EncryptedSuffix:   opts.EncryptedSuffix,
			UnencryptedRegex:  opts.UnencryptedRegex,
			EncryptedRegex:    opts.EncryptedRegex,
		},
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	}); err != nil {
		return nil, fmt.Errorf("encrypting tree: %w", err)
	}

	out, err := emit(tree)
	if err != nil {
		return nil, fmt.Errorf("emitting encrypted document: %w", err)
	}

	return out, nil
}

// NewVaultClient creates a Vault API client with an explicit address and
// token. No environment variables are consulted.
func NewVaultClient(address, token string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	client.SetToken(token)
	return client, nil
}

// AppRoleLogin authenticates to Vault using the AppRole auth method and
// returns the resulting client token. address is the full Vault server URL;
// approlePath is the auth mount path (typically "approle").
func AppRoleLogin(address, approlePath, roleID, secretID string) (string, error) {
	client, err := NewVaultClient(address, "")
	if err != nil {
		return "", err
	}
	secret, err := client.Logical().Write("auth/"+approlePath+"/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return "", fmt.Errorf("approle login at auth/%s/login: %w", approlePath, err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("approle login: empty auth response from Vault")
	}
	return secret.Auth.ClientToken, nil
}

// generateDataKey returns 32 cryptographically random bytes (AES-256).
func generateDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}
	return key, nil
}

// wrapDataKey calls the Vault Transit encrypt endpoint and returns the
// ciphertext blob (e.g. "vault:v1:…").
func wrapDataKey(client *vaultapi.Client, transitPath, keyName string, dataKey []byte) (string, error) {
	path := transitPath + "/encrypt/" + keyName
	secret, err := client.Logical().Write(path, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(dataKey),
	})
	if err != nil {
		return "", fmt.Errorf("vault transit encrypt (%s): %w", path, err)
	}
	ct, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected vault response: ciphertext not a string")
	}
	return ct, nil
}
