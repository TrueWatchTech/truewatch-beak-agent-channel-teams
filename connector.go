package beakteams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	platform "github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/internal/teams"
	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/state"
)

const (
	ID                  = "beak-agent-teams"
	Platform            = "teams"
	maxWebhookBodyBytes = 4 << 20
)

var ErrCredentialLogin = errors.New("teams connector uses credential login; create channel account from CredentialSchema")

type Connector struct{}

func NewConnector() sdk.Connector {
	return Connector{}
}

var _ sdk.Connector = Connector{}

// EventResult is returned by the inbound event handler.
type EventResult struct {
	Type        string              `json:"type"`
	Ignored     bool                `json:"ignored,omitempty"`
	Reason      string              `json:"reason,omitempty"`
	SessionUUID string              `json:"session_uuid,omitempty"`
	MessageUUID string              `json:"message_uuid,omitempty"`
	Inbound     *sdk.InboundMessage `json:"inbound,omitempty"`
}

func (Connector) Metadata() sdk.ConnectorMetadata {
	return sdk.ConnectorMetadata{
		ID:          ID,
		Platform:    Platform,
		Label:       "Microsoft Teams",
		Description: "Connect Microsoft Teams bot accounts to Beak Channel Gateway",
		Capabilities: sdk.Capabilities{
			LoginModes:       []string{sdk.LoginModeCredential},
			Text:             true,
			Media:            false,
			GroupChat:        true,
			DirectChat:       true,
			Stream:           false,
			Webhook:          true,
			BlockStreaming:   false,
			AckModes:         nil,
			RuntimeOwnership: "",
		},
	}
}

func (Connector) CredentialSchema(context.Context) sdk.CredentialSchema {
	return sdk.CredentialSchema{
		Type:       "object",
		LoginModes: []string{sdk.LoginModeCredential},
		Properties: map[string]sdk.CredentialField{
			"client_id": {
				Type:        "string",
				Title:       "Microsoft App ID (Client ID)",
				Description: "The Application (client) ID of the Azure Bot registration / Microsoft Entra ID app. Found in Azure Portal > App registrations > your bot app > Overview.\n",
				Secret:      false,
			},
			"client_secret": {
				Type:        "string",
				Title:       "Client Secret (App Password)",
				Description: "The client secret created under Azure Portal > App registrations > your bot app > Certificates & secrets. Keep this value private.\n",
				Secret:      true,
			},
			"tenant_id": {
				Type:        "string",
				Title:       "Tenant ID (optional)",
				Description: "Directory (tenant) ID for single-tenant deployments. Leave blank for multi-tenant (botframework.com tenant). When set, the token is acquired from https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token.\n",
				Secret:      false,
			},
		},
		Required: []string{
			"client_id",
			"client_secret",
		},
		AdditionalProperties: false,
	}
}

func (Connector) ValidateCredential(ctx context.Context, req sdk.CredentialValidationRequest) (*sdk.CredentialValidationResult, error) {
	credential := cloneMap(req.Credential)
	stateMap := cloneMap(req.State)

	client := platform.NewClient("", credentialStrings(credential))
	client.HTTPClient = req.Runtime.HTTPClient

	info, err := client.Validate(ctx)
	if err != nil {
		return &sdk.CredentialValidationResult{
			Valid:       false,
			AccountKey:  firstString(credential["account_id"], credential["client_id"], credential["bot_id"]),
			DisplayName: firstString(credential["display_name"], credential["client_id"], credential["account_id"]),
			Credential:  credential,
			State:       stateMap,
			Metadata: map[string]any{
				"platform": Platform,
				// A valid credential proves the app registration only; it does
				// not prove the bot is installed in any team/chat.
				"install_required": true,
				"validation_scope": "credential_only",
			},
			Error: err.Error(),
		}, nil
	}

	credential["account_id"] = info.AccountID
	credential["bot_id"] = info.BotID
	if strings.TrimSpace(info.BotID) != "" {
		stateMap["bot_id"] = info.BotID
	}
	if strings.TrimSpace(info.BotUserID) != "" {
		credential["bot_user_id"] = info.BotUserID
		stateMap["bot_user_id"] = info.BotUserID
	}
	// Standardized nested identity (in addition to the flat keys above, which
	// self-echo detection still reads) so generic conformance/host tooling can
	// find the bot's identity at a single well-known path.
	identities := teamsBotIdentityState(info.AccountID, info.BotUserID)
	if len(identities) > 0 {
		stateMap["bot_identity"] = identities[0]
		stateMap["bot_identities"] = identities
	}
	return &sdk.CredentialValidationResult{
		Valid:       true,
		AccountKey:  info.AccountID,
		DisplayName: firstString(info.DisplayName, info.BotName, info.AccountID),
		Credential:  credential,
		State:       stateMap,
		Metadata: map[string]any{
			"platform":         Platform,
			"bot_id":           info.BotID,
			"install_required": true,
			"validation_scope": "credential_only",
		},
	}, nil
}

func (Connector) StartLogin(context.Context, sdk.LoginStartRequest) (*sdk.LoginChallenge, error) {
	return nil, ErrCredentialLogin
}

func (Connector) PollLogin(context.Context, sdk.LoginPollRequest) (*sdk.LoginStatus, error) {
	return nil, ErrCredentialLogin
}

func (c Connector) Start(ctx context.Context, runtime sdk.Runtime) error {
	if runtime.Gateway == nil {
		return fmt.Errorf("%s connector requires sdk.Runtime.Gateway", Platform)
	}
	if _, err := runtime.Gateway.EnsureChannel(ctx, sdk.EnsureChannelRequest{
		WorkspaceUUID: runtime.WorkspaceUUID,
		Platform:      Platform,
		Name:          "Microsoft Teams",
		Config:        map[string]any{"bridge": ID},
	}); err != nil {
		return err
	}

	store := newConnectorStateStore(runtime.AccountStore)
	for _, account := range runtimeAccountCandidates(runtime) {
		store.seed(account)
		accountUUID := accountKey(account)
		if accountUUID == "" {
			return fmt.Errorf("%s account_uuid or account_id is required", Platform)
		}
		sessionUUID, err := runtime.Gateway.EnsureChannelLinkSession(ctx, sdk.EnsureChannelLinkSessionRequest{
			WorkspaceUUID:       runtime.WorkspaceUUID,
			Platform:            Platform,
			AccountUUID:         accountUUID,
			AgentParticipantID:  runtime.Gateway.AgentParticipantID(),
			BridgeParticipantID: runtime.Gateway.BridgeParticipantID(Platform),
		})
		if err != nil {
			return err
		}
		st, err := store.LoadAccount(ctx, accountUUID)
		if err != nil {
			return err
		}
		if st.ChannelLinkSession != sessionUUID {
			st.ChannelLinkSession = sessionUUID
			if err := store.SaveAccount(ctx, st); err != nil {
				return err
			}
		}
	}
	return nil
}

func (Connector) Send(ctx context.Context, runtime sdk.Runtime, req sdk.OutboundMessage) (*sdk.SendResult, error) {
	account, err := selectRuntimeAccount(runtime, req.AccountUUID)
	if err != nil {
		return nil, err
	}
	accountUUID := accountKey(account)
	if accountUUID == "" {
		return nil, fmt.Errorf("%s outbound account is required", Platform)
	}
	if strings.TrimSpace(req.ChatID) == "" {
		return nil, fmt.Errorf("%s outbound chat_id is required", Platform)
	}
	if strings.TrimSpace(req.Text) == "" {
		return nil, fmt.Errorf("%s outbound text is required", Platform)
	}

	store := newConnectorStateStore(runtime.AccountStore)
	store.seed(account)
	st, err := store.LoadAccount(ctx, accountUUID)
	if err != nil {
		return nil, err
	}

	// Bot Framework bots cannot send proactively without a conversation
	// reference (serviceUrl + conversation id) captured from a real inbound
	// activity. Fail explicitly when none has been seen for this chat.
	serviceURL := strings.TrimSpace(st.ServiceUrls[req.ChatID])
	if serviceURL == "" {
		return nil, fmt.Errorf("teams: no conversation reference for chat %s; bot must receive a message in this conversation before it can send proactively", req.ChatID)
	}

	client := platform.NewClient("", credentialStrings(account.Credential))
	client.HTTPClient = runtime.HTTPClient
	replyToID := firstString(req.ThreadID, req.Raw["reply_to_id"], req.Raw["replyToId"], req.Raw["thread_id"])
	messageID, err := client.SendText(ctx, serviceURL, req.ChatID, replyToID, req.Text, req.Format, req.Mentions, req.MentionAll)
	if err != nil {
		return nil, err
	}
	if err := store.SaveAccount(ctx, st); err != nil {
		return nil, err
	}
	return &sdk.SendResult{
		Platform:    Platform,
		AccountUUID: accountUUID,
		MessageID:   messageID,
	}, nil
}

// Acknowledge is part of the common Beak connector contract. Bot Framework
// does not expose a portable reaction/read/typing API for this connector, so
// unsupported is returned explicitly instead of forcing host-side branching.
func (Connector) Acknowledge(_ context.Context, _ sdk.Runtime, req sdk.OutboundAck) (*sdk.AckResult, error) {
	return &sdk.AckResult{
		Platform:    Platform,
		AccountUUID: strings.TrimSpace(req.AccountUUID),
		Mode:        strings.TrimSpace(req.Mode),
		Status:      "unsupported",
		Raw:         map[string]any{"reason": "unsupported_ack_mode"},
	}, nil
}

func (Connector) Stop(ctx context.Context, account sdk.ChannelAccount) error {
	_ = ctx
	_ = account
	return nil
}

// HandleWebhookRequest implements the sdk webhook entry point. Every inbound
// Bot Framework activity carries an Authorization: Bearer <JWT>; the SDK
// verifies that token (RS256 against the Bot Framework JWKS, iss/aud/exp/nbf,
// serviceUrl claim) before processing. Verification failures are returned as a
// Go error so the gateway can reject with 403.
func (c Connector) HandleWebhookRequest(ctx context.Context, runtime sdk.Runtime, account sdk.ChannelAccount, req *http.Request) (*sdk.WebhookResponse, error) {
	if req == nil || req.Body == nil {
		return nil, fmt.Errorf("%s webhook request body is required", Platform)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxWebhookBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s read webhook body: %w", Platform, err)
	}
	if len(body) > maxWebhookBodyBytes {
		return nil, fmt.Errorf("%s webhook body exceeds %d bytes", Platform, maxWebhookBodyBytes)
	}

	var activity platform.Activity
	if err := json.Unmarshal(body, &activity); err != nil {
		return nil, fmt.Errorf("%s decode webhook activity: %w", Platform, err)
	}

	expectedAudience := firstString(account.Credential["client_id"], account.Credential["bot_id"], account.Credential["account_id"])
	provider := platform.SharedJWKSProvider(runtime.HTTPClient)
	if err := platform.VerifyWebhookToken(ctx, provider, req.Header.Get("Authorization"), expectedAudience, activity.ServiceURL, activity.ChannelID, time.Now().UTC()); err != nil {
		return nil, err
	}

	if _, err := c.HandleWebhook(ctx, runtime, account, body); err != nil {
		return nil, err
	}
	// Bot Framework only requires a 2xx; the body is ignored for activities.
	return &sdk.WebhookResponse{StatusCode: http.StatusOK}, nil
}

// HandleWebhook parses an already-verified Bot Framework activity body and runs
// the inbound flow. It is separated from HandleWebhookRequest so tests can drive
// the inbound logic directly and inspect the resulting EventResult.
func (c Connector) HandleWebhook(ctx context.Context, runtime sdk.Runtime, account sdk.ChannelAccount, body []byte) (*EventResult, error) {
	var activity platform.Activity
	if err := json.Unmarshal(body, &activity); err != nil {
		return nil, fmt.Errorf("%s decode webhook activity: %w", Platform, err)
	}
	return c.processMessageEvent(ctx, runtime, account, &activity)
}

// processMessageEvent implements the inbound standard flow. The conversation
// reference (serviceUrl + conversation + tenant) is persisted on EVERY inbound
// activity — including echoes, conversationUpdate, and non-text — because it is
// the only way the bot can later send proactively. Beak messages are created
// only for genuine inbound text.
func (c Connector) processMessageEvent(ctx context.Context, runtime sdk.Runtime, account sdk.ChannelAccount, activity *platform.Activity) (*EventResult, error) {
	if runtime.Gateway == nil {
		return nil, fmt.Errorf("%s event handling requires sdk.Runtime.Gateway", Platform)
	}
	if activity == nil {
		return nil, fmt.Errorf("%s activity is required", Platform)
	}
	accountUUID := accountKey(account)
	if accountUUID == "" {
		return nil, fmt.Errorf("%s account_uuid or account_id is required", Platform)
	}

	store := newConnectorStateStore(runtime.AccountStore)
	store.seed(account)
	st, err := store.LoadAccount(ctx, accountUUID)
	if err != nil {
		return nil, err
	}

	botIDs := teamsBotIDs(activity, st, account)

	// Normalize chat identity up-front so the conversation reference can be
	// keyed consistently.
	chatType := sdk.ChatTypeGroup
	switch strings.ToLower(strings.TrimSpace(activity.Conversation.ConversationType)) {
	case "personal":
		chatType = sdk.ChatTypeDirect
	case "channel", "groupchat":
		chatType = sdk.ChatTypeGroup
	}
	chatID := strings.TrimSpace(activity.Conversation.ID)
	stateKey := Platform + ":" + chatType + ":" + chatID
	now := time.Now().UTC()
	if st.StreamConnectedAt.IsZero() {
		st.StreamConnectedAt = now
	}
	st.StreamConnectionState = sdk.RuntimeHealthStateConnected
	st.StreamLastActivityAt = now
	st.StreamSessionExpired = false

	// Persist the conversation reference on every activity, before any filter,
	// so outbound sends work even when the triggering activity is ignored.
	if chatID != "" && strings.TrimSpace(activity.ServiceURL) != "" {
		if tenant := strings.TrimSpace(activity.Conversation.TenantID); tenant != "" {
			st.TenantID = tenant
		}
		ref := map[string]any{
			"serviceUrl":   activity.ServiceURL,
			"conversation": activity.Conversation,
			"tenantId":     activity.Conversation.TenantID,
		}
		if data, err := json.Marshal(ref); err == nil {
			st.ConversationReferences[stateKey] = data
		}
		st.ServiceUrls[chatID] = activity.ServiceURL
	}
	if err := store.SaveAccount(ctx, st); err != nil {
		return nil, err
	}

	// conversationUpdate (bot added/removed, members changed) carries no text;
	// the reference is already saved, so just acknowledge.
	if activity.Type == "conversationUpdate" {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "conversation_update"}, nil
	}
	if activity.Type != "message" {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "unsupported_event_type"}, nil
	}

	senderID := firstString(activity.From.AADObjectID, activity.From.ID)
	text := activityText(activity)
	messageID := strings.TrimSpace(activity.ID)

	// Self-echo: drop the bot's own messages (from == bot id, or from == the
	// recipient, which for an echo is the bot itself).
	if matchesTeamsBot(activity.From.ID, botIDs) || matchesTeamsBot(activity.From.AADObjectID, botIDs) {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "self_echo"}, nil
	}
	if activity.Recipient.ID != "" && strings.EqualFold(activity.From.ID, activity.Recipient.ID) {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "self_echo"}, nil
	}

	// Mention detection: scan entities for a mention of the bot.
	mentionedMe := false
	mentionAll := false
	mentions := make([]sdk.MentionIdentity, 0, len(activity.Entities))
	for _, raw := range activity.Entities {
		var ent platform.MentionEntity
		if err := json.Unmarshal(raw, &ent); err != nil {
			continue
		}
		if !strings.EqualFold(ent.Type, "mention") {
			continue
		}
		id := firstString(ent.Mentioned.AADObjectID, ent.Mentioned.ID)
		name := strings.TrimSpace(ent.Mentioned.Name)
		if id != "" {
			idType := "teams_user_id"
			if strings.TrimSpace(ent.Mentioned.AADObjectID) != "" {
				idType = "aad_object_id"
			}
			mentions = append(mentions, sdk.MentionIdentity{ID: id, IDType: idType, DisplayName: name})
		}
		if matchesTeamsBot(ent.Mentioned.ID, botIDs) || matchesTeamsBot(ent.Mentioned.AADObjectID, botIDs) {
			mentionedMe = true
			text = stripTeamsMention(text, ent)
		}
		if strings.EqualFold(id, "everyone") || strings.EqualFold(id, "all") || strings.EqualFold(name, "everyone") {
			mentionAll = true
		}
	}
	text = strings.TrimSpace(text)

	// Text-only filter (skip non-text / incomplete activities).
	if chatID == "" || senderID == "" || messageID == "" || (text == "" && !mentionedMe) {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "unsupported_message_type"}, nil
	}

	// Dedupe.
	dedupeKey := accountUUID + ":message:" + messageID
	if _, ok := st.InboundSeen[dedupeKey]; ok {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "duplicate", SessionUUID: st.PeerSessions[stateKey]}, nil
	}

	inbound := sdk.InboundMessage{
		WorkspaceUUID:     runtime.WorkspaceUUID,
		Platform:          Platform,
		AccountUUID:       accountUUID,
		ChannelUUID:       runtime.Channel.UUID,
		ChatType:          chatType,
		ChatID:            chatID,
		ThreadID:          strings.TrimSpace(activity.ReplyToID),
		ChatDisplayName:   teamsChatDisplayName(activity, chatType),
		ChatIdentity:      teamsChatIdentity(activity, chatType, chatID),
		SenderID:          senderID,
		SenderDisplayName: strings.TrimSpace(activity.From.Name),
		MessageID:         messageID,
		Text:              text,
		ReferencedMessage: teamsReferencedMessage(activity, chatType, chatID),
		DedupeKey:         dedupeKey,
		Mentions:          mentions,
		MentionedMe:       mentionedMe,
		MentionAll:        mentionAll,
		Raw: map[string]any{
			"activity_id": messageID,
			"chat_id":     chatID,
			"service_url": activity.ServiceURL,
			"from":        senderID,
			"channel_id":  activity.ChannelID,
			"reply_to_id": activity.ReplyToID,
		},
	}

	// Ensure the chat session (identity includes account uuid → two bots in the
	// same group never share a session).
	sessionUUID, err := runtime.Gateway.EnsureChatSession(ctx, sdk.EnsureChatSessionRequest{
		WorkspaceUUID:       runtime.WorkspaceUUID,
		Platform:            Platform,
		AccountUUID:         accountUUID,
		ChatType:            chatType,
		ChatID:              chatID,
		ThreadID:            inbound.ThreadID,
		ChatDisplayName:     inbound.ChatDisplayName,
		ChatIdentity:        inbound.ChatIdentity,
		SenderID:            senderID,
		AgentParticipantID:  runtime.Gateway.AgentParticipantID(),
		BridgeParticipantID: runtime.Gateway.BridgeParticipantID(Platform),
		Metadata: map[string]any{
			"source":            Platform,
			"platform":          Platform,
			"account_uuid":      accountUUID,
			"chat_display_name": inbound.ChatDisplayName,
			"chat_identity":     inbound.ChatIdentity,
		},
	})
	if err != nil {
		return nil, err
	}

	messageUUID, err := runtime.Gateway.CreateMessage(ctx, sdk.CreateMessageRequest{
		WorkspaceUUID: runtime.WorkspaceUUID,
		SessionUUID:   sessionUUID,
		SenderID:      sdk.IMPersonParticipantID(Platform, chatType, chatID, senderID),
		Content:       text,
		DedupeKey:     dedupeKey,
		Metadata: map[string]any{
			"source":              Platform,
			"platform":            Platform,
			"account_uuid":        accountUUID,
			"chat_type":           chatType,
			"chat_id":             chatID,
			"thread_id":           inbound.ThreadID,
			"chat_identity":       inbound.ChatIdentity,
			"chat_display_name":   inbound.ChatDisplayName,
			"sender_display_name": inbound.SenderDisplayName,
			"referenced_message":  inbound.ReferencedMessage,
			"teams_chat_type":     chatType,
			"teams_chat_id":       chatID,
			"inbound_message":     inbound,
		},
	})
	if err != nil {
		return nil, err
	}

	st.PeerSessions[stateKey] = sessionUUID
	st.InboundSeen[dedupeKey] = now.Format(time.RFC3339Nano)
	st.StreamLastEventAt = now
	st.StreamLastActivityAt = now
	if err := store.SaveAccount(ctx, st); err != nil {
		return nil, err
	}

	return &EventResult{
		Type:        activity.Type,
		SessionUUID: sessionUUID,
		MessageUUID: messageUUID,
		Inbound:     &inbound,
	}, nil
}

func teamsBotIdentityState(appID, channelBotID string) []map[string]any {
	appID = strings.TrimSpace(appID)
	channelBotID = strings.TrimSpace(channelBotID)
	if channelBotID == "" && appID != "" {
		channelBotID = "28:" + appID
	}
	identities := make([]map[string]any, 0, 2)
	if appID != "" {
		identities = append(identities, map[string]any{"id": appID, "id_type": "app_id"})
	}
	if channelBotID != "" && !strings.EqualFold(channelBotID, appID) {
		identities = append(identities, map[string]any{"id": channelBotID, "id_type": "channel_account_id"})
	}
	return identities
}

func teamsBotIDs(activity *platform.Activity, st *state.AccountState, account sdk.ChannelAccount) map[string]struct{} {
	ids := make(map[string]struct{})
	add := func(value any) {
		id := strings.TrimSpace(stringValue(value))
		if id == "" {
			return
		}
		ids[strings.ToLower(id)] = struct{}{}
		if !strings.Contains(id, ":") {
			ids[strings.ToLower("28:"+id)] = struct{}{}
		}
	}
	if activity != nil {
		add(activity.Recipient.ID)
		add(activity.Recipient.AADObjectID)
	}
	if st != nil {
		add(st.BotID)
	}
	add(account.Credential["client_id"])
	add(account.Credential["bot_id"])
	add(account.Credential["bot_user_id"])
	add(account.State["bot_id"])
	add(account.State["bot_user_id"])
	if identity, ok := account.State["bot_identity"].(map[string]any); ok {
		add(identity["id"])
	}
	switch identities := account.State["bot_identities"].(type) {
	case []any:
		for _, item := range identities {
			if identity, ok := item.(map[string]any); ok {
				add(identity["id"])
			}
		}
	case []map[string]any:
		for _, identity := range identities {
			add(identity["id"])
		}
	}
	return ids
}

func matchesTeamsBot(id string, botIDs map[string]struct{}) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return false
	}
	_, ok := botIDs[id]
	return ok
}

func stripTeamsMention(text string, mention platform.MentionEntity) string {
	candidates := []string{strings.TrimSpace(mention.Text)}
	if name := strings.TrimSpace(mention.Mentioned.Name); name != "" {
		candidates = append(candidates, "<at>"+name+"</at>")
	}
	for _, candidate := range candidates {
		if candidate != "" {
			text = strings.ReplaceAll(text, candidate, "")
		}
	}
	return strings.TrimSpace(text)
}

func activityText(activity *platform.Activity) string {
	if activity == nil {
		return ""
	}
	if text := strings.TrimSpace(activity.Text); text != "" {
		return text
	}
	fragments := make([]string, 0)
	appendJSONText(activity.Value, 0, &fragments)
	for _, attachment := range activity.Attachments {
		before := len(fragments)
		appendJSONText(attachment.Content, 0, &fragments)
		if len(fragments) == before {
			fragments = append(fragments, strings.TrimSpace(attachment.Name))
		}
	}
	return joinUniqueText(fragments)
}

func appendJSONText(raw json.RawMessage, depth int, out *[]string) {
	if len(raw) == 0 || depth > 8 {
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return
	}
	appendStructuredText(value, depth, out)
}

func appendStructuredText(value any, depth int, out *[]string) {
	if depth > 8 || value == nil {
		return
	}
	switch typed := value.(type) {
	case string:
		if text := strings.TrimSpace(typed); text != "" {
			*out = append(*out, text)
		}
	case []any:
		for _, item := range typed {
			appendStructuredText(item, depth+1, out)
		}
	case map[string]any:
		for _, key := range []string{"title", "text", "value", "label", "fallbackText", "altText", "speak"} {
			if item, ok := typed[key]; ok {
				appendStructuredText(item, depth+1, out)
			}
		}
		for _, key := range []string{"body", "items", "columns", "facts", "actions"} {
			if item, ok := typed[key]; ok {
				appendStructuredText(item, depth+1, out)
			}
		}
	}
}

func joinUniqueText(values []string) string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, "\n")
}

func teamsChatDisplayName(activity *platform.Activity, chatType string) string {
	if activity == nil {
		return ""
	}
	if chatType == sdk.ChatTypeDirect {
		return firstString(activity.Conversation.Name, activity.From.Name)
	}
	return firstString(activity.ChannelData.Channel.Name, activity.Conversation.Name, activity.ChannelData.Team.Name)
}

func teamsChatIdentity(activity *platform.Activity, chatType, chatID string) sdk.ChatIdentity {
	return sdk.ChatIdentity{
		ID:          strings.TrimSpace(chatID),
		IDType:      "conversation_id",
		Type:        strings.TrimSpace(chatType),
		DisplayName: teamsChatDisplayName(activity, chatType),
	}
}

func teamsReferencedMessage(activity *platform.Activity, chatType, chatID string) *sdk.ReferencedMessage {
	if activity == nil || strings.TrimSpace(activity.ReplyToID) == "" {
		return nil
	}
	return &sdk.ReferencedMessage{
		Platform:    Platform,
		MessageID:   strings.TrimSpace(activity.ReplyToID),
		ChatType:    chatType,
		ChatID:      strings.TrimSpace(chatID),
		ThreadID:    strings.TrimSpace(activity.ReplyToID),
		MessageType: "message",
		Raw: map[string]any{
			"fetched":     false,
			"fetch_error": "bot connector API does not expose arbitrary activity retrieval",
		},
	}
}

// connectorStateStore adapts sdk.AccountStore to typed state.AccountState.
type connectorStateStore struct {
	mu           sync.Mutex
	accounts     map[string]*state.AccountState
	accountStore sdk.AccountStore
}

func newConnectorStateStore(accountStore sdk.AccountStore) *connectorStateStore {
	return &connectorStateStore{
		accounts:     make(map[string]*state.AccountState),
		accountStore: accountStore,
	}
}

func (s *connectorStateStore) seed(account sdk.ChannelAccount) {
	accountID := accountKey(account)
	if accountID == "" {
		return
	}
	// Registration only; LoadAccount is the single point that populates the
	// cache (rehydrating from the AccountStore when present), so seed must not
	// pre-insert an empty state that would shadow persisted state.
	_ = accountID
}

func (s *connectorStateStore) LoadAccount(ctx context.Context, accountID string) (*state.AccountState, error) {
	s.mu.Lock()
	if st, ok := s.accounts[accountID]; ok {
		s.mu.Unlock()
		return st, nil
	}
	accountStore := s.accountStore
	s.mu.Unlock()

	st := &state.AccountState{AccountID: accountID}
	if accountStore != nil {
		raw, err := accountStore.LoadChannelAccountState(ctx, accountID)
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if data, err := json.Marshal(raw); err == nil {
				_ = json.Unmarshal(data, st)
			}
			st.AccountID = accountID
		}
	}
	st.EnsureMaps()

	s.mu.Lock()
	s.accounts[accountID] = st
	s.mu.Unlock()
	return st, nil
}

func (s *connectorStateStore) SaveAccount(ctx context.Context, account *state.AccountState) error {
	if err := state.TouchAccount(account); err != nil {
		return err
	}
	s.mu.Lock()
	s.accounts[account.AccountID] = account
	accountStore := s.accountStore
	s.mu.Unlock()
	if accountStore != nil {
		data, err := json.Marshal(account)
		if err != nil {
			return err
		}
		var persisted map[string]any
		if err := json.Unmarshal(data, &persisted); err != nil {
			return err
		}
		return accountStore.SaveChannelAccountState(ctx, account.AccountID, persisted)
	}
	return nil
}

func runtimeAccountCandidates(runtime sdk.Runtime) []sdk.ChannelAccount {
	seen := make(map[string]bool)
	var out []sdk.ChannelAccount
	add := func(account sdk.ChannelAccount) {
		key := accountKey(account)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, account)
	}
	add(runtime.Account)
	for _, account := range runtime.Accounts {
		add(account)
	}
	return out
}

func selectRuntimeAccount(runtime sdk.Runtime, accountUUID string) (sdk.ChannelAccount, error) {
	accountUUID = strings.TrimSpace(accountUUID)
	candidates := runtimeAccountCandidates(runtime)
	if accountUUID != "" {
		for _, account := range candidates {
			if accountMatches(account, accountUUID) {
				return account, nil
			}
		}
		return sdk.ChannelAccount{}, fmt.Errorf("%s account %s not found in runtime", Platform, accountUUID)
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return sdk.ChannelAccount{}, fmt.Errorf("%s outbound account is required", Platform)
	}
	return sdk.ChannelAccount{}, fmt.Errorf("%s outbound account is ambiguous; account_uuid is required", Platform)
}

func accountMatches(account sdk.ChannelAccount, accountID string) bool {
	return strings.TrimSpace(account.UUID) == accountID ||
		strings.TrimSpace(stringValue(account.Credential["account_id"])) == accountID ||
		strings.TrimSpace(stringValue(account.Credential["bot_id"])) == accountID
}

func accountKey(account sdk.ChannelAccount) string {
	return firstString(account.UUID, account.Credential["account_id"], account.Credential["bot_id"])
}

func credentialStrings(credential map[string]any) map[string]string {
	out := make(map[string]string, len(credential))
	for key, value := range credential {
		out[key] = stringValue(value)
	}
	return out
}

func cloneMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func firstString(values ...any) string {
	for _, value := range values {
		if s := strings.TrimSpace(stringValue(value)); s != "" {
			return s
		}
	}
	return ""
}
