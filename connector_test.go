package beakteams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
)

func TestConnectorImplementsInterface(t *testing.T) {
	var _ sdk.Connector = NewConnector()
}

func TestConnectorMetadata(t *testing.T) {
	meta := NewConnector().Metadata()
	if meta.ID != ID {
		t.Fatalf("id=%q want %q", meta.ID, ID)
	}
	if meta.Platform != Platform {
		t.Fatalf("platform=%q want %q", meta.Platform, Platform)
	}
	if meta.Label != "Microsoft Teams" {
		t.Fatalf("label=%q want %q", meta.Label, "Microsoft Teams")
	}
	if !meta.Capabilities.Text {
		t.Fatal("expected text capability")
	}
}

func TestConnectorCredentialSchema(t *testing.T) {
	schema := NewConnector().CredentialSchema(context.Background())
	if schema.Type != "object" {
		t.Fatalf("type=%q", schema.Type)
	}
	if schema.AdditionalProperties {
		t.Fatal("additionalProperties must be false")
	}
	if _, ok := schema.Properties["client_id"]; !ok {
		t.Fatalf("missing credential field client_id")
	}
	if _, ok := schema.Properties["client_secret"]; !ok {
		t.Fatalf("missing credential field client_secret")
	}
	if !schema.Properties["client_secret"].Secret {
		t.Fatalf("client_secret must be marked secret")
	}
	if _, ok := schema.Properties["tenant_id"]; !ok {
		t.Fatalf("missing credential field tenant_id")
	}
	// Must not leak backend-only fields.
	for _, banned := range []string{"base_url", "callback_url", "webhook_url", "offset"} {
		if _, ok := schema.Properties[banned]; ok {
			t.Fatalf("credential schema leaks backend field %q", banned)
		}
	}
}

func TestHandleWebhookRequestClassifiesInvalidBodyAndAuthentication(t *testing.T) {
	c := Connector{}
	account := teamsAccount("acct-1", "app-id")

	tests := []struct {
		name       string
		body       []byte
		wantStatus int
		wantCode   string
	}{
		{name: "invalid body", body: []byte(`{`), wantStatus: http.StatusBadRequest, wantCode: "invalid_request_body"},
		{
			name:       "oversized body",
			body:       []byte(strings.Repeat("x", maxWebhookBodyBytes+1)),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   "request_body_too_large",
		},
		{
			name: "missing bearer token",
			body: activityBody(teamsActivity{
				Type:             "message",
				ID:               "activity-1",
				ServiceURL:       testServiceURL,
				ConversationID:   "conversation-1",
				ConversationType: "personal",
				FromID:           "user-1",
				RecipientID:      "app-id",
			}),
			wantStatus: http.StatusForbidden,
			wantCode:   "channel_webhook_auth_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(tt.body)))
			_, err := c.HandleWebhookRequest(context.Background(), makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore()), account, req)
			if err == nil {
				t.Fatal("HandleWebhookRequest() error = nil")
			}
			statusErr, ok := err.(interface{ HTTPStatusCode() int })
			if !ok || statusErr.HTTPStatusCode() != tt.wantStatus {
				t.Fatalf("webhook status error = %#v, want status %d", err, tt.wantStatus)
			}
			codeErr, ok := err.(interface{ ErrorCode() string })
			if !ok || codeErr.ErrorCode() != tt.wantCode {
				t.Fatalf("webhook error code = %#v, want %q", err, tt.wantCode)
			}
		})
	}
}

// tokenOK is a successful client_credentials token response.
func tokenOK() map[string]any {
	return map[string]any{"access_token": "app-token", "token_type": "Bearer", "expires_in": 3600}
}

func TestValidateCredential_Success(t *testing.T) {
	c := Connector{}
	res, err := c.ValidateCredential(context.Background(), sdk.CredentialValidationRequest{
		Credential: map[string]any{"client_id": testClientID, "client_secret": testClientSec},
		Runtime:    sdk.Runtime{HTTPClient: httpClientReturning(tokenOK())},
	})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected Valid=true, got error %q", res.Error)
	}
	if res.AccountKey != testClientID {
		t.Fatalf("account key=%q want %q", res.AccountKey, testClientID)
	}
	if res.State["bot_id"] != testClientID {
		t.Fatalf("bot identity not persisted to state: %#v", res.State)
	}
	if res.State["bot_user_id"] != "28:"+testClientID {
		t.Fatalf("channel bot identity not persisted to state: %#v", res.State)
	}
	if identities, ok := res.State["bot_identities"].([]map[string]any); !ok || len(identities) != 2 {
		t.Fatalf("expected app and channel bot identities, got %#v", res.State["bot_identities"])
	}
}

func TestValidateCredential_InvalidToken(t *testing.T) {
	c := Connector{}
	client := &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})}
	// Use a body that carries an OAuth error so the client surfaces it.
	client = httpClientReturning(map[string]any{"error": "invalid_client", "error_description": "bad secret"})
	res, err := c.ValidateCredential(context.Background(), sdk.CredentialValidationRequest{
		Credential: map[string]any{"client_id": testClientID, "client_secret": "bad"},
		Runtime:    sdk.Runtime{HTTPClient: client},
	})
	if err != nil {
		t.Fatalf("invalid token must not return a Go error, got %v", err)
	}
	if res.Valid {
		t.Fatal("expected Valid=false")
	}
	if res.Error == "" {
		t.Fatal("expected Error to be populated")
	}
}

func TestValidateCredential_HTTPClientInjected(t *testing.T) {
	var sawPath, sawMethod string
	client := &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		sawPath = req.URL.Path
		sawMethod = req.Method
		return testJSONResponse(tokenOK())
	})}
	c := Connector{}
	if _, err := c.ValidateCredential(context.Background(), sdk.CredentialValidationRequest{
		Credential: map[string]any{"client_id": testClientID, "client_secret": testClientSec},
		Runtime:    sdk.Runtime{HTTPClient: client},
	}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if sawPath != "/botframework.com/oauth2/v2.0/token" {
		t.Fatalf("expected token endpoint, saw %q", sawPath)
	}
	if sawMethod != http.MethodPost {
		t.Fatalf("expected POST, saw %q", sawMethod)
	}
}

func TestStart_MissingGatewayReturnsError(t *testing.T) {
	c := Connector{}
	if err := c.Start(context.Background(), sdk.Runtime{}); err == nil {
		t.Fatal("expected error when Gateway is nil")
	}
}

func TestStart_Success(t *testing.T) {
	c := Connector{}
	store := newFakeSDKAccountStore()
	rt := makeRuntime(&fakeSDKGateway{}, store, teamsAccount("acct-1", "bot-1"))
	if err := c.Start(context.Background(), rt); err != nil {
		t.Fatalf("start: %v", err)
	}
	saved, _ := store.LoadChannelAccountState(context.Background(), "acct-1")
	if saved["channel_link_session"] != "link-acct-1" {
		t.Fatalf("expected channel link session persisted, got %#v", saved)
	}
}

func TestInbound_ConversationUpdateIgnored(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "conversationUpdate", ID: "cu1", ServiceURL: testServiceURL,
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})
	if !res.Ignored || res.Reason != "conversation_update" {
		t.Fatalf("expected conversation_update ignore, got ignored=%v reason=%q", res.Ignored, res.Reason)
	}
}

func inbound(t *testing.T, a teamsActivity) *EventResult {
	t.Helper()
	c := Connector{}
	res, err := c.HandleWebhook(context.Background(), makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore()), teamsAccount("acct-1", "bot-1"), activityBody(a))
	if err != nil {
		t.Fatalf("handle webhook: %v", err)
	}
	return res
}

func TestInbound_DirectText(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "message", ID: "1", ServiceURL: testServiceURL, Text: "hi",
		ConversationID: "D1", ConversationType: "personal", FromID: "U_HUMAN",
	})
	if res.Ignored {
		t.Fatalf("unexpected ignore: %q", res.Reason)
	}
	if res.Inbound == nil || res.Inbound.ChatType != sdk.ChatTypeDirect {
		t.Fatalf("expected direct chat, got %#v", res.Inbound)
	}
}

func TestInbound_GroupText(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "message", ID: "2", ServiceURL: testServiceURL, Text: "hi",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})
	if res.Ignored || res.Inbound == nil || res.Inbound.ChatType != sdk.ChatTypeGroup {
		t.Fatalf("expected group chat, got ignored=%v %#v", res.Ignored, res.Inbound)
	}
}

func TestInbound_MentionMe(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "message", ID: "3", ServiceURL: testServiceURL, Text: "<at>bot</at> hello",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN", MentionBotID: "bot-1",
	})
	if res.Ignored || res.Inbound == nil || !res.Inbound.MentionedMe {
		t.Fatalf("expected MentionedMe=true, got ignored=%v %#v", res.Ignored, res.Inbound)
	}
}

func TestInbound_SelfEchoIgnored(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "message", ID: "4", ServiceURL: testServiceURL, Text: "echo",
		ConversationID: "C1", ConversationType: "channel", FromID: "bot-1",
	})
	if !res.Ignored || res.Reason != "self_echo" {
		t.Fatalf("expected self_echo ignore, got ignored=%v reason=%q", res.Ignored, res.Reason)
	}
}

func TestInbound_NonTextIgnored(t *testing.T) {
	res := inbound(t, teamsActivity{
		Type: "message", ID: "5", ServiceURL: testServiceURL, Text: "",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})
	if !res.Ignored || res.Reason != "unsupported_message_type" {
		t.Fatalf("expected non-text ignore, got ignored=%v reason=%q", res.Ignored, res.Reason)
	}
}

func TestInbound_DuplicateIgnored(t *testing.T) {
	c := Connector{}
	rt := makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore())
	account := teamsAccount("acct-1", "bot-1")
	body := activityBody(teamsActivity{
		Type: "message", ID: "dup", ServiceURL: testServiceURL, Text: "hi",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})
	if _, err := c.HandleWebhook(context.Background(), rt, account, body); err != nil {
		t.Fatalf("first: %v", err)
	}
	res, err := c.HandleWebhook(context.Background(), rt, account, body)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !res.Ignored || res.Reason != "duplicate" {
		t.Fatalf("expected duplicate ignore, got ignored=%v reason=%q", res.Ignored, res.Reason)
	}
}

func TestInbound_SavesState(t *testing.T) {
	c := Connector{}
	store := newFakeSDKAccountStore()
	if _, err := c.HandleWebhook(context.Background(), makeRuntime(&fakeSDKGateway{}, store), teamsAccount("acct-1", "bot-1"),
		activityBody(teamsActivity{
			Type: "message", ID: "6", ServiceURL: testServiceURL, Text: "hi",
			ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
		})); err != nil {
		t.Fatalf("handle: %v", err)
	}
	saved, _ := store.LoadChannelAccountState(context.Background(), "acct-1")
	refs, _ := saved["conversation_references"].(map[string]any)
	urls, _ := saved["service_urls"].(map[string]any)
	if len(refs) == 0 || len(urls) == 0 {
		t.Fatalf("expected conversation_references and service_urls persisted, got %#v", saved)
	}
	if saved[sdk.RuntimeHealthKeyStreamConnectionState] != sdk.RuntimeHealthStateConnected {
		t.Fatalf("expected connected health state, got %#v", saved)
	}
	if saved[sdk.RuntimeHealthKeyStreamLastEventAt] == nil {
		t.Fatalf("expected last event timestamp, got %#v", saved)
	}
}

func TestInbound_UsesRecipientIdentityForMentionAndKeepsMentionOnly(t *testing.T) {
	c := Connector{}
	account := teamsAccount("acct-1", "app-id")
	body, _ := json.Marshal(map[string]any{
		"type": "message", "id": "mention-1", "channelId": "msteams",
		"serviceUrl": testServiceURL, "text": "<at>Beak Bot</at>",
		"conversation": map[string]any{"id": "C1", "conversationType": "channel"},
		"from":         map[string]any{"id": "29:user", "name": "Alice"},
		"recipient":    map[string]any{"id": "28:app-id", "name": "Beak Bot"},
		"entities": []map[string]any{{
			"type": "mention", "text": "<at>Beak Bot</at>",
			"mentioned": map[string]any{"id": "28:app-id", "name": "Beak Bot"},
		}},
	})
	res, err := c.HandleWebhook(context.Background(), makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore()), account, body)
	if err != nil {
		t.Fatalf("handle webhook: %v", err)
	}
	if res.Ignored || res.Inbound == nil {
		t.Fatalf("mention-only message must reach Beak: %#v", res)
	}
	if !res.Inbound.MentionedMe || res.Inbound.Text != "" {
		t.Fatalf("expected bot mention stripped while preserving follow-up event: %#v", res.Inbound)
	}
	if len(res.Inbound.Mentions) != 1 || res.Inbound.Mentions[0].ID != "28:app-id" {
		t.Fatalf("expected normalized mentions, got %#v", res.Inbound.Mentions)
	}
}

func TestInbound_OtherMentionDoesNotMentionBot(t *testing.T) {
	c := Connector{}
	body, _ := json.Marshal(map[string]any{
		"type": "message", "id": "mention-2", "serviceUrl": testServiceURL,
		"text":         "<at>Alice</at> please check",
		"conversation": map[string]any{"id": "C1", "conversationType": "channel"},
		"from":         map[string]any{"id": "29:user-2"},
		"recipient":    map[string]any{"id": "28:app-id"},
		"entities": []map[string]any{{
			"type": "mention", "text": "<at>Alice</at>",
			"mentioned": map[string]any{"id": "29:alice", "name": "Alice"},
		}},
	})
	res, err := c.HandleWebhook(context.Background(), makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore()), teamsAccount("acct-1", "app-id"), body)
	if err != nil {
		t.Fatalf("handle webhook: %v", err)
	}
	if res.Inbound == nil || res.Inbound.MentionedMe {
		t.Fatalf("another user's mention must not imply MentionedMe: %#v", res.Inbound)
	}
	if res.Inbound.Text != "<at>Alice</at> please check" {
		t.Fatalf("other mentions must remain in text, got %q", res.Inbound.Text)
	}
}

func TestInbound_CardTextNamesAndReferenceUseCommonFields(t *testing.T) {
	c := Connector{}
	gw := &fakeSDKGateway{}
	body, _ := json.Marshal(map[string]any{
		"type": "message", "id": "card-1", "serviceUrl": testServiceURL,
		"replyToId":    "parent-1",
		"conversation": map[string]any{"id": "C1", "name": "Operations", "conversationType": "channel"},
		"channelData":  map[string]any{"team": map[string]any{"id": "team-1", "name": "SRE"}, "channel": map[string]any{"id": "channel-1", "name": "Alerts"}},
		"from":         map[string]any{"id": "29:user", "aadObjectId": "aad-user", "name": "Alice"},
		"recipient":    map[string]any{"id": "28:app-id"},
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     map[string]any{"type": "AdaptiveCard", "body": []map[string]any{{"type": "TextBlock", "text": "CPU alert"}, {"type": "FactSet", "facts": []map[string]any{{"title": "Host", "value": "api-1"}}}}},
		}},
	})
	res, err := c.HandleWebhook(context.Background(), makeRuntime(gw, newFakeSDKAccountStore()), teamsAccount("acct-1", "app-id"), body)
	if err != nil {
		t.Fatalf("handle webhook: %v", err)
	}
	in := res.Inbound
	if in == nil || !strings.Contains(in.Text, "CPU alert") || !strings.Contains(in.Text, "api-1") {
		t.Fatalf("expected adaptive card text, got %#v", in)
	}
	if in.ChatDisplayName != "Alerts" || in.SenderDisplayName != "Alice" || in.ChatIdentity.ID != "C1" {
		t.Fatalf("expected common chat/sender identity fields, got %#v", in)
	}
	if in.ThreadID != "parent-1" || in.ReferencedMessage == nil || in.ReferencedMessage.MessageID != "parent-1" {
		t.Fatalf("expected common reference/thread fields, got %#v", in)
	}
	if len(gw.chatSessions) != 1 || gw.chatSessions[0].ThreadID != "parent-1" || gw.chatSessions[0].ChatDisplayName != "Alerts" {
		t.Fatalf("common session request lost thread/name: %#v", gw.chatSessions)
	}
}

func TestSend_Text(t *testing.T) {
	c := Connector{}
	account := teamsAccount("acct-1", "bot-1")
	store := newFakeSDKAccountStore()
	rt := makeRuntime(&fakeSDKGateway{}, store, account)
	rt.HTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/oauth2/v2.0/token") {
			return testJSONResponse(tokenOK())
		}
		return testJSONResponse(map[string]any{"id": "act-1"})
	})}

	// Capture a conversation reference for chat C1 first.
	if _, err := c.HandleWebhook(context.Background(), rt, account, activityBody(teamsActivity{
		Type: "message", ID: "seed", ServiceURL: testServiceURL, Text: "seed",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})); err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	res, err := c.Send(context.Background(), rt, sdk.OutboundMessage{AccountUUID: "acct-1", ChatID: "C1", Text: "hi"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.MessageID != "act-1" {
		t.Fatalf("message id=%q want act-1", res.MessageID)
	}
}

func TestSend_ThreadAndMentionMappedToTeamsActivity(t *testing.T) {
	c := Connector{}
	account := teamsAccount("acct-1", "app-id")
	store := newFakeSDKAccountStore()
	rt := makeRuntime(&fakeSDKGateway{}, store, account)
	var sentPath string
	var sent map[string]any
	rt.HTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/oauth2/v2.0/token") {
			return testJSONResponse(tokenOK())
		}
		sentPath = req.URL.Path
		if err := json.NewDecoder(req.Body).Decode(&sent); err != nil {
			t.Fatalf("decode outbound: %v", err)
		}
		return testJSONResponse(map[string]any{"id": "reply-1"})
	})}
	if _, err := c.HandleWebhook(context.Background(), rt, account, activityBody(teamsActivity{
		Type: "message", ID: "seed-thread", ServiceURL: testServiceURL, Text: "seed",
		ConversationID: "C1", ConversationType: "channel", FromID: "29:user",
	})); err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	_, err := c.Send(context.Background(), rt, sdk.OutboundMessage{
		AccountUUID: "acct-1", ChatID: "C1", ThreadID: "parent-1", Text: "checking",
		Mentions: []sdk.MentionIdentity{{ID: "29:alice", DisplayName: "Alice"}},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.HasSuffix(sentPath, "/activities/parent-1") || sent["replyToId"] != "parent-1" {
		t.Fatalf("thread reply not mapped: path=%q payload=%#v", sentPath, sent)
	}
	if !strings.Contains(stringValue(sent["text"]), "<at>Alice</at>") {
		t.Fatalf("mention markup missing: %#v", sent)
	}
	if entities, ok := sent["entities"].([]any); !ok || len(entities) != 1 {
		t.Fatalf("mention entity missing: %#v", sent)
	}
}

func TestAcknowledge_ExplicitlyUnsupported(t *testing.T) {
	result, err := (Connector{}).Acknowledge(context.Background(), sdk.Runtime{}, sdk.OutboundAck{AccountUUID: "acct-1", Mode: "reaction"})
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if result.Status != "unsupported" || result.Platform != Platform || result.AccountUUID != "acct-1" {
		t.Fatalf("unexpected ack result: %#v", result)
	}
}

func TestSend_MissingChatID(t *testing.T) {
	c := Connector{}
	account := teamsAccount("acct-1", "bot-1")
	rt := makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore(), account)
	if _, err := c.Send(context.Background(), rt, sdk.OutboundMessage{AccountUUID: "acct-1", Text: "hi"}); err == nil {
		t.Fatal("expected error for missing chat_id")
	}
}

func TestSend_MissingAccount(t *testing.T) {
	c := Connector{}
	rt := makeRuntime(&fakeSDKGateway{}, newFakeSDKAccountStore())
	if _, err := c.Send(context.Background(), rt, sdk.OutboundMessage{AccountUUID: "ghost", ChatID: "C1", Text: "hi"}); err == nil {
		t.Fatal("expected error for unknown account")
	}
}
