package teams

import "encoding/json"

// BotInfo is the normalized identity returned by Validate. For Bot Framework
// there is no "get bot info" call; a successful client_credentials token proves
// the app registration is valid, so the identity is the app (client) id itself.
type BotInfo struct {
	AccountID   string
	BotID       string
	BotUserID   string
	DisplayName string
	BotName     string
}

// tokenResponse models the Microsoft identity platform token endpoint response
// for the client_credentials grant. On failure the error/error_description
// fields are populated (and the HTTP status is usually non-2xx).
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Conversation is the Bot Framework conversation account on an Activity.
type Conversation struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	IsGroup          bool   `json:"isGroup"`
	ConversationType string `json:"conversationType"`
	TenantID         string `json:"tenantId"`
}

// ChannelAccount is the Bot Framework account object used for from/recipient.
type ChannelAccount struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AADObjectID string `json:"aadObjectId"`
}

// Activity is the inbound Bot Framework activity. Entities is left raw so the
// connector can scan for mention entities without a fixed schema.
type Activity struct {
	Type         string            `json:"type"`
	ID           string            `json:"id"`
	ChannelID    string            `json:"channelId"`
	ServiceURL   string            `json:"serviceUrl"`
	ReplyToID    string            `json:"replyToId"`
	Locale       string            `json:"locale"`
	Text         string            `json:"text"`
	TextFormat   string            `json:"textFormat"`
	Conversation Conversation      `json:"conversation"`
	From         ChannelAccount    `json:"from"`
	Recipient    ChannelAccount    `json:"recipient"`
	Entities     []json.RawMessage `json:"entities"`
	Attachments  []Attachment      `json:"attachments"`
	Value        json.RawMessage   `json:"value"`
	ChannelData  ChannelData       `json:"channelData"`
}

type ChannelData struct {
	Tenant  ChannelInfo `json:"tenant"`
	Team    ChannelInfo `json:"team"`
	Channel ChannelInfo `json:"channel"`
}

type ChannelInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Attachment struct {
	ContentType string          `json:"contentType"`
	ContentURL  string          `json:"contentUrl"`
	Name        string          `json:"name"`
	Content     json.RawMessage `json:"content"`
}

// MentionEntity models a Bot Framework "mention" entity inside Activity.Entities.
type MentionEntity struct {
	Type      string         `json:"type"`
	Mentioned ChannelAccount `json:"mentioned"`
	Text      string         `json:"text"`
}

// sendActivityResponse is the response from POSTing an activity to the connector
// service; it carries the created activity id.
type sendActivityResponse struct {
	ID string `json:"id"`
}

// openIDConfig is the Bot Framework OpenID configuration document; only the
// jwks_uri is needed to locate the signing keys.
type openIDConfig struct {
	JWKSURI string `json:"jwks_uri"`
}

// jwks is a JSON Web Key Set.
type jwks struct {
	Keys []jwk `json:"keys"`
}

// jwk is a single JSON Web Key. For RSA signing keys, n/e are base64url-encoded
// big-endian integers (the modulus and public exponent).
type jwk struct {
	Kty          string   `json:"kty"`
	Kid          string   `json:"kid"`
	Use          string   `json:"use"`
	N            string   `json:"n"`
	E            string   `json:"e"`
	X5C          []string `json:"x5c"`
	Endorsements []string `json:"endorsements"`
}
