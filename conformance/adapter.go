// Package teamsconformance adapts the generated Microsoft Teams SDK to the
// beak-channel-sdk-conformance test harness. It only converts between the
// sdk.* and conformance.* type families; no business logic lives here.
package teamsconformance

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"

	beakteams "github.com/TrueWatchTech/truewatch-beak-agent-channel-teams"
	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
	conformance "gitlab.jiagouyun.com/guance/beak-agent-channel-sdk/beak-channel-sdk-conformance"
)

// adapter implements the conformance provider interfaces on top of the
// generated beakteams.Connector.
type adapter struct {
	conn sdk.Connector
	raw  beakteams.Connector
}

func newAdapter() *adapter {
	return &adapter{conn: beakteams.NewConnector(), raw: beakteams.Connector{}}
}

func (a *adapter) Metadata() conformance.ConnectorMetadata {
	m := a.conn.Metadata()
	return conformance.ConnectorMetadata{
		ID:          m.ID,
		Platform:    m.Platform,
		Label:       m.Label,
		Description: m.Description,
		Capabilities: conformance.Capabilities{
			LoginModes:          m.Capabilities.LoginModes,
			Text:                m.Capabilities.Text,
			Media:               m.Capabilities.Media,
			GroupChat:           m.Capabilities.GroupChat,
			DirectChat:          m.Capabilities.DirectChat,
			Stream:              m.Capabilities.Stream,
			Webhook:             m.Capabilities.Webhook,
			WebhookRegistration: m.Capabilities.WebhookRegistration,
			BlockStreaming:      m.Capabilities.BlockStreaming,
			AckModes:            m.Capabilities.AckModes,
			RuntimeOwnership:    m.Capabilities.RuntimeOwnership,
		},
	}
}

func (a *adapter) CredentialSchema(ctx context.Context) conformance.CredentialSchema {
	s := a.conn.CredentialSchema(ctx)
	properties := make(map[string]conformance.CredentialField, len(s.Properties))
	for key, field := range s.Properties {
		properties[key] = conformance.CredentialField{
			Type:        field.Type,
			Title:       field.Title,
			Description: field.Description,
			Secret:      field.Secret,
		}
	}
	return conformance.CredentialSchema{
		Type:                 s.Type,
		LoginModes:           s.LoginModes,
		Properties:           properties,
		Required:             s.Required,
		AdditionalProperties: s.AdditionalProperties,
	}
}

func (a *adapter) ValidateCredential(ctx context.Context, req conformance.CredentialValidationRequest) (*conformance.CredentialValidationResult, error) {
	sdkReq := sdk.CredentialValidationRequest{
		WorkspaceUUID: req.WorkspaceUUID,
		ChannelUUID:   req.ChannelUUID,
		Platform:      req.Platform,
		Credential:    req.Credential,
		State:         req.State,
		Runtime: sdk.Runtime{
			HTTPClient: fakeAuthClient(),
		},
	}
	result, err := a.conn.ValidateCredential(ctx, sdkReq)
	if err != nil || result == nil {
		return nil, err
	}
	return &conformance.CredentialValidationResult{
		Valid:       result.Valid,
		AccountKey:  result.AccountKey,
		DisplayName: result.DisplayName,
		Credential:  result.Credential,
		State:       result.State,
		Metadata:    result.Metadata,
		Error:       result.Error,
	}, nil
}

func (a *adapter) ParseInbound(ctx context.Context, fixture conformance.InboundFixture) ([]conformance.InboundMessage, error) {
	account := sdk.ChannelAccount{
		UUID:          fixture.AccountUUID,
		WorkspaceUUID: fixture.WorkspaceUUID,
		ChannelUUID:   fixture.ChannelUUID,
		Platform:      fixture.Platform,
		Credential:    fixture.Credential,
		State:         fixture.AccountState,
	}
	runtime := sdk.Runtime{
		WorkspaceUUID: fixture.WorkspaceUUID,
		Channel: sdk.Channel{
			UUID:          fixture.ChannelUUID,
			WorkspaceUUID: fixture.WorkspaceUUID,
			Platform:      fixture.Platform,
		},
		Gateway:      newFakeGateway(),
		AccountStore: newFakeAccountStore(),
	}

	result, err := a.raw.HandleWebhook(ctx, runtime, account, fixture.Raw)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Inbound == nil {
		return []conformance.InboundMessage{}, nil
	}
	in := result.Inbound
	return []conformance.InboundMessage{
		{
			WorkspaceUUID:   in.WorkspaceUUID,
			Platform:        in.Platform,
			AccountUUID:     in.AccountUUID,
			ChannelUUID:     in.ChannelUUID,
			ChatType:        in.ChatType,
			ChatID:          in.ChatID,
			ThreadID:        in.ThreadID,
			ChatDisplayName: in.ChatDisplayName,
			ChatAvatarURL:   in.ChatAvatarURL,
			ChatIdentity: conformance.ChatIdentity{
				ID:          in.ChatIdentity.ID,
				IDType:      in.ChatIdentity.IDType,
				Type:        in.ChatIdentity.Type,
				DisplayName: in.ChatIdentity.DisplayName,
				AvatarURL:   in.ChatIdentity.AvatarURL,
			},
			SenderID:          in.SenderID,
			SenderDisplayName: in.SenderDisplayName,
			MessageID:         in.MessageID,
			Text:              in.Text,
			ReferencedMessage: convertReferencedMessage(in.ReferencedMessage),
			DedupeKey:         in.DedupeKey,
			Mentions:          convertMentions(in.Mentions),
			MentionedMe:       in.MentionedMe,
			MentionAll:        in.MentionAll,
			Raw:               in.Raw,
		}}, nil
}

func convertReferencedMessage(ref *sdk.ReferencedMessage) *conformance.ReferencedMessage {
	if ref == nil {
		return nil
	}
	return &conformance.ReferencedMessage{
		Platform:          ref.Platform,
		MessageID:         ref.MessageID,
		ChatType:          ref.ChatType,
		ChatID:            ref.ChatID,
		ThreadID:          ref.ThreadID,
		RootID:            ref.RootID,
		SenderID:          ref.SenderID,
		SenderDisplayName: ref.SenderDisplayName,
		MessageType:       ref.MessageType,
		Text:              ref.Text,
		CreatedAt:         ref.CreatedAt,
		Raw:               ref.Raw,
	}
}

func (a *adapter) Acknowledge(ctx context.Context, req conformance.OutboundAck) (*conformance.AckResult, error) {
	result, err := a.conn.Acknowledge(ctx, sdk.Runtime{}, sdk.OutboundAck{
		WorkspaceUUID:     req.WorkspaceUUID,
		Platform:          req.Platform,
		AccountUUID:       req.AccountUUID,
		ChannelUUID:       req.ChannelUUID,
		SessionUUID:       req.SessionUUID,
		SourceMessageUUID: req.SourceMessageUUID,
		ChatType:          req.ChatType,
		ChatID:            req.ChatID,
		TargetMessageID:   req.TargetMessageID,
		Intent:            req.Intent,
		Action:            req.Action,
		Mode:              req.Mode,
		Emoji:             req.Emoji,
		Raw:               req.Raw,
	})
	if err != nil || result == nil {
		return nil, err
	}
	return &conformance.AckResult{
		Platform:    result.Platform,
		AccountUUID: result.AccountUUID,
		Mode:        result.Mode,
		Status:      result.Status,
		ReactionID:  result.ReactionID,
		Raw:         result.Raw,
	}, nil
}

func convertMentions(mentions []sdk.MentionIdentity) []conformance.MentionIdentity {
	if len(mentions) == 0 {
		return nil
	}
	out := make([]conformance.MentionIdentity, len(mentions))
	for i, m := range mentions {
		out[i] = conformance.MentionIdentity{ID: m.ID, IDType: m.IDType, DisplayName: m.DisplayName}
	}
	return out
}

// fakeAuthClient stubs the Microsoft Teams credential-validation endpoint so
// ValidateCredential can run without a real network call.
func fakeAuthClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"access_token":"app-token","token_type":"Bearer","expires_in":3600}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// fakeGateway is a minimal sdk.Gateway that fabricates deterministic IDs.
type fakeGateway struct {
	mu       sync.Mutex
	sessions int
	messages int
}

func newFakeGateway() *fakeGateway { return &fakeGateway{} }

func (g *fakeGateway) EnsureChannel(context.Context, sdk.EnsureChannelRequest) (string, error) {
	return "channel-1", nil
}

func (g *fakeGateway) EnsureChannelLinkSession(_ context.Context, req sdk.EnsureChannelLinkSessionRequest) (string, error) {
	return "link-" + req.AccountUUID, nil
}

func (g *fakeGateway) EnsureChatSession(_ context.Context, req sdk.EnsureChatSessionRequest) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sessions++
	return "session-" + req.AccountUUID + "-" + req.ChatType + "-" + req.ChatID, nil
}

func (g *fakeGateway) CreateMessage(context.Context, sdk.CreateMessageRequest) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.messages++
	return "message-1", nil
}

func (g *fakeGateway) StreamSession(context.Context, sdk.StreamSessionRequest, func(sdk.StreamEvent) error) error {
	return nil
}

func (g *fakeGateway) AgentParticipantID() string { return "agent:agent-1" }

func (g *fakeGateway) BridgeParticipantID(platform string) string {
	return sdk.BridgeParticipantID(platform)
}

// fakeAccountStore is an in-memory sdk.AccountStore.
type fakeAccountStore struct {
	mu     sync.Mutex
	states map[string]map[string]any
}

func newFakeAccountStore() *fakeAccountStore {
	return &fakeAccountStore{states: make(map[string]map[string]any)}
}

func (s *fakeAccountStore) LoadChannelAccountState(_ context.Context, accountUUID string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[accountUUID], nil
}

func (s *fakeAccountStore) SaveChannelAccountState(_ context.Context, accountUUID string, state map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[accountUUID] = state
	return nil
}
