package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"terraform-provider-sops/internal/sopsencrypt"
)

var (
	_ resource.Resource                = &encryptedJSONResource{}
	_ resource.ResourceWithConfigure   = &encryptedJSONResource{}
	_ resource.ResourceWithImportState = &encryptedJSONResource{}
)

type encryptedJSONResource struct{ pd *sopsProviderData }

type encryptedJSONModel struct {
	ID                types.String `tfsdk:"id"`
	Content           types.String `tfsdk:"content"`
	VaultKeyName      types.String `tfsdk:"vault_key_name"`
	UnencryptedSuffix types.String `tfsdk:"unencrypted_suffix"`
	EncryptedSuffix   types.String `tfsdk:"encrypted_suffix"`
	UnencryptedRegex  types.String `tfsdk:"unencrypted_regex"`
	EncryptedRegex    types.String `tfsdk:"encrypted_regex"`
	Pretty            types.Bool   `tfsdk:"pretty"`
	Ciphertext        types.String `tfsdk:"ciphertext"`
}

func NewEncryptedJSONResource() resource.Resource { return &encryptedJSONResource{} }

func (r *encryptedJSONResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypted_json"
}

func (r *encryptedJSONResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `Encrypts a JSON document using SOPS (AES-256-GCM) with a Vault Transit
key and stores the resulting ciphertext in state.

Define the document structure with ` + "`jsonencode()`" + ` in a local and reference it
via the content attribute:

    locals {
      secrets = jsonencode({
        database = { host = "db.example.com", password = var.db_pass }
        api_key  = var.api_key
      })
    }

    resource "sops_encrypted_json" "example" {
      content        = local.secrets
      vault_key_name = "my-key"
    }

The ciphertext is stable across plans until content or vault_key_name changes,
at which point the resource is replaced and re-encrypted.`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"content": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "JSON-encoded document to encrypt. Use jsonencode() to build the structure.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"vault_key_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the Vault Transit key used to wrap the data key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"unencrypted_suffix": schema.StringAttribute{
				Optional:    true,
				Description: "Keys whose names end with this suffix are left in plaintext. Mutually exclusive with other scope options.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encrypted_suffix": schema.StringAttribute{
				Optional:    true,
				Description: "Only keys whose names end with this suffix are encrypted. Mutually exclusive with other scope options.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"unencrypted_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Keys whose names match this regex are left in plaintext. Mutually exclusive with other scope options.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encrypted_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Only keys whose names match this regex are encrypted. Mutually exclusive with other scope options.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"pretty": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Indent the SOPS JSON output. Defaults to false.",
				Default:     booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"ciphertext": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "SOPS-encrypted JSON document. Decryptable with `sops -d --input-type json`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *encryptedJSONResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*sopsProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *sopsProviderData, got %T", req.ProviderData))
		return
	}
	r.pd = pd
}

func (r *encryptedJSONResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data encryptedJSONModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.validateScope(data); err != nil {
		resp.Diagnostics.AddError("Invalid scope configuration", err.Error())
		return
	}

	ciphertext, err := r.encrypt(data)
	if err != nil {
		resp.Diagnostics.AddError("SOPS encryption failed", err.Error())
		return
	}

	data.ID = types.StringValue(data.VaultKeyName.ValueString())
	data.Ciphertext = types.StringValue(ciphertext)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is a no-op: ciphertext in state remains valid until inputs change.
func (r *encryptedJSONResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data encryptedJSONModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is never reached because all meaningful attributes carry RequiresReplace.
func (r *encryptedJSONResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("unexpected update", "sops_encrypted_json does not support in-place updates")
}

func (r *encryptedJSONResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {}

func (r *encryptedJSONResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *encryptedJSONResource) validateScope(data encryptedJSONModel) error {
	set := 0
	for _, v := range []types.String{
		data.UnencryptedSuffix, data.EncryptedSuffix,
		data.UnencryptedRegex, data.EncryptedRegex,
	} {
		if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("at most one of unencrypted_suffix, encrypted_suffix, unencrypted_regex, encrypted_regex may be set")
	}
	return nil
}

func (r *encryptedJSONResource) encrypt(data encryptedJSONModel) (string, error) {
	client, err := sopsencrypt.NewVaultClient(r.pd.vaultAddress, r.pd.vaultToken)
	if err != nil {
		return "", err
	}
	opts := sopsencrypt.EncryptOpts{
		UnencryptedSuffix: data.UnencryptedSuffix.ValueString(),
		EncryptedSuffix:   data.EncryptedSuffix.ValueString(),
		UnencryptedRegex:  data.UnencryptedRegex.ValueString(),
		EncryptedRegex:    data.EncryptedRegex.ValueString(),
		PrettyJSON:        data.Pretty.ValueBool(),
	}
	return sopsencrypt.EncryptToJSON(client, r.pd.vaultTransitEngine, data.VaultKeyName.ValueString(), data.Content.ValueString(), opts)
}
