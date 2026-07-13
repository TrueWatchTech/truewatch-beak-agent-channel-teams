package beakteams

import "context"

type API interface {
	RegisterChannel(Channel) error
}

type Plugin struct{}

type Channel struct{}

type Metadata struct {
	ID          string
	Platform    string
	Label       string
	Description string
}

type Capabilities struct {
	DirectChat     bool
	GroupChat      bool
	Text           bool
	Media          bool
	BlockStreaming bool
}

type SettingsSchema struct {
	Type                 string         `json:"type"`
	AdditionalProperties bool           `json:"additionalProperties"`
	Properties           map[string]any `json:"properties"`
	Required             []string       `json:"required,omitempty"`
}

func New() Plugin {
	return Plugin{}
}

func Register(api API) error {
	return New().Register(api)
}

func (Plugin) Register(api API) error {
	return api.RegisterChannel(Channel{})
}

func (Plugin) Channel() Channel {
	return Channel{}
}

func (Channel) Metadata() Metadata {
	return Metadata{
		ID:          ID,
		Platform:    Platform,
		Label:       "Microsoft Teams",
		Description: "Microsoft Teams connector for Beak channel gateway sessions",
	}
}

func (Channel) Capabilities() Capabilities {
	return Capabilities{
		DirectChat:     true,
		GroupChat:      true,
		Text:           true,
		Media:          false,
		BlockStreaming: false,
	}
}

func (Channel) SettingsSchema() SettingsSchema {
	return SettingsSchema{
		Type:                 "object",
		AdditionalProperties: false,
		Required: []string{
			"client_id",
			"client_secret",
		},
		Properties: map[string]any{
			"client_id": map[string]any{
				"type":        "string",
				"title":       "Microsoft App ID (Client ID)",
				"description": "The Application (client) ID of the Azure Bot registration / Microsoft Entra ID app. Found in Azure Portal > App registrations > your bot app > Overview.\n",
				"secret":      false,
			},
			"client_secret": map[string]any{
				"type":        "string",
				"title":       "Client Secret (App Password)",
				"description": "The client secret created under Azure Portal > App registrations > your bot app > Certificates & secrets. Keep this value private.\n",
				"secret":      true,
			},
			"tenant_id": map[string]any{
				"type":        "string",
				"title":       "Tenant ID (optional)",
				"description": "Directory (tenant) ID for single-tenant deployments. Leave blank for multi-tenant (botframework.com tenant). When set, the token is acquired from https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token.\n",
				"secret":      false,
			},
		},
	}
}

// CheckHealth reports plugin-level readiness. The compatibility layer carries no
// credential, so this is a static check: the connector is registered and ready.
// Per-account credential health is verified by Connector.ValidateCredential.
func (Channel) CheckHealth(context.Context) error {
	return nil
}
