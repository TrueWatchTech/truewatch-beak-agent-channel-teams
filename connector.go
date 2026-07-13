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

	platform "github.com/TrueWatch/beak-agent-channel-teams/internal/teams"
	"github.com/TrueWatch/beak-agent-channel-teams/sdk"
	"github.com/TrueWatch/beak-agent-channel-teams/state"
)

const (
	ID       = "beak-agent-teams"
	Platform = "teams"
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
			LoginModes:     []string{sdk.LoginModeCredential},
			Text:           true,
			Media:          false,
			GroupChat:      true,
			DirectChat:     true,
			Stream:         false,
			Webhook:        true,
			BlockStreaming: false,
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
	if id := firstString(info.BotUserID, info.BotID, info.AccountID); id != "" {
		stateMap["bot_identity"] = map[string]any{"id": id}
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
	messageID, err := client.SendText(ctx, serviceURL, req.ChatID, req.Text, req.Format, req.Mentions, req.MentionAll)
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
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("%s read webhook body: %w", Platform, err)
	}

	var activity platform.Activity
	if err := json.Unmarshal(body, &activity); err != nil {
		return nil, fmt.Errorf("%s decode webhook activity: %w", Platform, err)
	}

	expectedAudience := firstString(account.Credential["client_id"], account.Credential["bot_id"], account.Credential["account_id"])
	provider := platform.NewJWKSProvider(runtime.HTTPClient)
	if err := platform.VerifyWebhookToken(ctx, provider, req.Header.Get("Authorization"), expectedAudience, activity.ServiceURL, time.Now().UTC()); err != nil {
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

	botID := firstString(st.BotID, account.Credential["bot_id"], account.Credential["client_id"], account.State["bot_id"])

	// Normalize chat identity up-front so the conversation reference can be
	// keyed consistently.
	chatType := sdk.ChatTypeGroup
	switch activity.Conversation.ConversationType {
	case "personal":
		chatType = sdk.ChatTypeDirect
	case "channel", "groupChat":
		chatType = sdk.ChatTypeGroup
	}
	chatID := strings.TrimSpace(activity.Conversation.ID)
	stateKey := Platform + ":" + chatType + ":" + chatID

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
		if err := store.SaveAccount(ctx, st); err != nil {
			return nil, err
		}
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
	text := strings.TrimSpace(activity.Text)
	messageID := strings.TrimSpace(activity.ID)

	// Self-echo: drop the bot's own messages (from == bot id, or from == the
	// recipient, which for an echo is the bot itself).
	if botID != "" && (activity.From.ID == botID || activity.From.AADObjectID == botID) {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "self_echo"}, nil
	}
	if activity.Recipient.ID != "" && activity.From.ID == activity.Recipient.ID {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "self_echo"}, nil
	}

	// Mention detection: scan entities for a mention of the bot.
	mentionedMe := false
	for _, raw := range activity.Entities {
		var ent struct {
			Type      string `json:"type"`
			Mentioned struct {
				ID string `json:"id"`
			} `json:"mentioned"`
		}
		if err := json.Unmarshal(raw, &ent); err != nil {
			continue
		}
		if strings.EqualFold(ent.Type, "mention") && botID != "" && ent.Mentioned.ID == botID {
			mentionedMe = true
			break
		}
	}

	// Text-only filter (skip non-text / incomplete activities).
	if chatID == "" || senderID == "" || text == "" {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "unsupported_message_type"}, nil
	}

	// Dedupe.
	dedupeKey := accountUUID + ":message:" + messageID
	if _, ok := st.InboundSeen[dedupeKey]; ok {
		return &EventResult{Type: activity.Type, Ignored: true, Reason: "duplicate", SessionUUID: st.PeerSessions[stateKey]}, nil
	}

	inbound := sdk.InboundMessage{
		WorkspaceUUID: runtime.WorkspaceUUID,
		Platform:      Platform,
		AccountUUID:   accountUUID,
		ChannelUUID:   runtime.Channel.UUID,
		ChatType:      chatType,
		ChatID:        chatID,
		SenderID:      senderID,
		MessageID:     messageID,
		Text:          text,
		DedupeKey:     dedupeKey,
		MentionedMe:   mentionedMe,
		Raw: map[string]any{
			"activity_id": messageID,
			"chat_id":     chatID,
			"service_url": activity.ServiceURL,
			"from":        senderID,
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
		SenderID:            senderID,
		AgentParticipantID:  runtime.Gateway.AgentParticipantID(),
		BridgeParticipantID: runtime.Gateway.BridgeParticipantID(Platform),
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
			"source":          Platform,
			"teams_chat_type": chatType,
			"teams_chat_id":   chatID,
			"inbound_message": inbound,
		},
	})
	if err != nil {
		return nil, err
	}

	st.PeerSessions[stateKey] = sessionUUID
	st.InboundSeen[dedupeKey] = time.Now().UTC().Format(time.RFC3339Nano)
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
