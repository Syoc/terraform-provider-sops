package provider

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"terraform-provider-sops/internal/sopsencrypt"
)

var (
	_ datasource.DataSource              = &sopsConfigDataSource{}
	_ datasource.DataSourceWithConfigure = &sopsConfigDataSource{}
)

type sopsConfigDataSource struct{ pd *sopsProviderData }

type sopsConfigModel struct {
	ID           types.String `tfsdk:"id"`
	VaultKeyName types.String `tfsdk:"vault_key_name"`
	PathRegexes  types.List   `tfsdk:"path_regexes"`
	Content      types.String `tfsdk:"content"`
}

func NewSOPSConfigDataSource() datasource.DataSource { return &sopsConfigDataSource{} }

func (d *sopsConfigDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config"
}

func (d *sopsConfigDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `Renders the content of a ` + "`.sops.yaml`" + ` configuration file for the
HashiCorp Vault Transit backend.

Each entry in path_regexes becomes one creation_rule that points to the
named Vault Transit key. When path_regexes is omitted, a single catch-all
creation_rule is emitted with no path_regex, which matches all files.

Use the output with the ` + "`local_file`" + ` resource to write the file to disk:

    data "sops_config" "example" {
      vault_key_name = "my-key"
    }

    resource "local_file" "sops_yaml" {
      content  = data.sops_config.example.content
      filename = "${path.module}/.sops.yaml"
    }`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 of the rendered content.",
			},
			"vault_key_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the Vault Transit key referenced in every creation rule.",
			},
			"path_regexes": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: `Path regexes for which the Vault Transit key is applied. Each regex
becomes one creation_rule entry in the output. When omitted, a single
catch-all creation_rule is generated with no path_regex, matching all files.`,
			},
			"content": schema.StringAttribute{
				Computed:    true,
				Description: "Rendered .sops.yaml YAML content.",
			},
		},
	}
}

func (d *sopsConfigDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*sopsProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *sopsProviderData, got %T", req.ProviderData))
		return
	}
	d.pd = pd
}

func (d *sopsConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data sopsConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var pathRegexes []string
	if !data.PathRegexes.IsNull() && !data.PathRegexes.IsUnknown() {
		resp.Diagnostics.Append(data.PathRegexes.ElementsAs(ctx, &pathRegexes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	content, err := sopsencrypt.GenerateSOPSConfig(
		d.pd.vaultAddress,
		d.pd.vaultTransitEngine,
		data.VaultKeyName.ValueString(),
		pathRegexes,
	)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate SOPS config", err.Error())
		return
	}

	h := sha256.Sum256([]byte(content))
	data.ID = types.StringValue(fmt.Sprintf("%x", h))
	data.Content = types.StringValue(content)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
