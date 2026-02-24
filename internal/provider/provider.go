package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"terraform-provider-sops/internal/sopsencrypt"
)

var _ provider.Provider = &sopsProvider{}

type sopsProvider struct {
	version string
}

type sopsProviderModel struct {
	VaultAddress       types.String `tfsdk:"vault_address"`
	VaultToken         types.String `tfsdk:"vault_token"`
	VaultTransitEngine types.String `tfsdk:"vault_transit_engine"`
	VaultRoleID        types.String `tfsdk:"vault_role_id"`
	VaultSecretID      types.String `tfsdk:"vault_secret_id"`
	VaultApprolePath   types.String `tfsdk:"vault_approle_path"`
}

// sopsProviderData carries resolved credentials to every data source and resource.
// The vault token is kept here and injected directly into the vault API client —
// it is never written to the process environment.
type sopsProviderData struct {
	vaultAddress       string
	vaultToken         string
	vaultTransitEngine string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &sopsProvider{version: version}
	}
}

func (p *sopsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
	resp.Version = p.version
}

func (p *sopsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encrypt secrets using SOPS with HashiCorp Vault Transit as the key backend.",
		Attributes: map[string]schema.Attribute{
			"vault_address": schema.StringAttribute{
				Description: "Vault server URL. Falls back to the VAULT_ADDR environment variable.",
				Optional:    true,
			},
			"vault_token": schema.StringAttribute{
				Description: "Vault token. Falls back to the VAULT_TOKEN environment variable. " +
					"Mutually exclusive with vault_role_id / vault_secret_id.",
				Optional:  true,
				Sensitive: true,
			},
			"vault_transit_engine": schema.StringAttribute{
				Description: "Mount path for the Vault Transit secrets engine. Defaults to 'transit'.",
				Optional:    true,
			},
			"vault_role_id": schema.StringAttribute{
				Description: "AppRole role ID. Falls back to the VAULT_ROLE_ID environment variable. " +
					"Must be used together with vault_secret_id. Mutually exclusive with vault_token.",
				Optional: true,
			},
			"vault_secret_id": schema.StringAttribute{
				Description: "AppRole secret ID. Falls back to the VAULT_SECRET_ID environment variable. " +
					"Must be used together with vault_role_id. Mutually exclusive with vault_token.",
				Optional:  true,
				Sensitive: true,
			},
			"vault_approle_path": schema.StringAttribute{
				Description: "Mount path for the AppRole auth method. Defaults to 'approle'.",
				Optional:    true,
			},
		},
	}
}

func (p *sopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config sopsProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Explicit provider config takes precedence; env vars are the fallback.
	// Credentials are stored in sopsProviderData and injected directly into
	// the vault API client — os.Setenv is intentionally not called here.
	vaultAddress := resolveString(config.VaultAddress, "VAULT_ADDR")
	vaultTransitEngine := resolveStringDefault(config.VaultTransitEngine, "transit")

	if vaultAddress == "" {
		resp.Diagnostics.AddError(
			"Missing Vault address",
			"Set vault_address in the provider block or the VAULT_ADDR environment variable.",
		)
		return
	}

	vaultToken := resolveString(config.VaultToken, "VAULT_TOKEN")
	roleID := resolveString(config.VaultRoleID, "VAULT_ROLE_ID")
	secretID := resolveString(config.VaultSecretID, "VAULT_SECRET_ID")

	hasToken := vaultToken != ""
	hasAppRole := roleID != "" || secretID != ""

	if hasToken && hasAppRole {
		resp.Diagnostics.AddError(
			"Conflicting Vault credentials",
			"Provide either vault_token or AppRole credentials (vault_role_id + vault_secret_id), not both.",
		)
		return
	}

	switch {
	case hasToken:
		// token already resolved above

	case roleID != "" && secretID != "":
		approlePath := resolveStringDefault(config.VaultApprolePath, "approle")
		token, err := sopsencrypt.AppRoleLogin(vaultAddress, approlePath, roleID, secretID)
		if err != nil {
			resp.Diagnostics.AddError("AppRole authentication failed", err.Error())
			return
		}
		vaultToken = token

	case roleID != "" || secretID != "":
		resp.Diagnostics.AddError(
			"Incomplete AppRole credentials",
			"Both vault_role_id and vault_secret_id are required for AppRole authentication.",
		)
		return

	default:
		resp.Diagnostics.AddError(
			"Missing Vault credentials",
			"Provide vault_token (or VAULT_TOKEN) or both vault_role_id and vault_secret_id for AppRole authentication.",
		)
		return
	}

	pd := &sopsProviderData{
		vaultAddress:       vaultAddress,
		vaultToken:         vaultToken,
		vaultTransitEngine: vaultTransitEngine,
	}
	resp.DataSourceData = pd
	resp.ResourceData = pd
}

func (p *sopsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSOPSConfigDataSource,
	}
}

func (p *sopsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewEncryptedJSONResource,
		NewEncryptedYAMLResource,
	}
}

// resolveString returns the explicit config value if set, otherwise the named env var.
func resolveString(attr types.String, envVar string) string {
	if !attr.IsNull() && !attr.IsUnknown() && attr.ValueString() != "" {
		return attr.ValueString()
	}
	return os.Getenv(envVar)
}

// resolveStringDefault returns the explicit config value if set, otherwise defaultVal.
func resolveStringDefault(attr types.String, defaultVal string) string {
	if !attr.IsNull() && !attr.IsUnknown() && attr.ValueString() != "" {
		return attr.ValueString()
	}
	return defaultVal
}
