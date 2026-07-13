package beakteams

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
)

const (
	testClientID   = "test-client-id"
	testClientSec  = "test-client-secret"
	testServiceURL = "https://smba.trafficmanager.net/amer/"
)

// fakeSDKGateway records the EnsureChatSession / CreateMessage calls it receives.
type fakeSDKGateway struct {
	mu           sync.Mutex
	chatSessions []sdk.EnsureChatSessionRequest
	messages     []sdk.CreateMessageRequest
}

func (g *fakeSDKGateway) EnsureChannel(_ context.Context, _ sdk.EnsureChannelRequest) (string, error) {
	return "channel-1", nil
}

func (g *fakeSDKGateway) EnsureChannelLinkSession(_ context.Context, req sdk.EnsureChannelLinkSessionRequest) (string, error) {
	return "link-" + req.AccountUUID, nil
}

func (g *fakeSDKGateway) EnsureChatSession(_ context.Context, req sdk.EnsureChatSessionRequest) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.chatSessions = append(g.chatSessions, req)
	return "session-" + req.AccountUUID + "-" + req.ChatType + "-" + req.ChatID, nil
}

func (g *fakeSDKGateway) CreateMessage(_ context.Context, req sdk.CreateMessageRequest) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.messages = append(g.messages, req)
	return "message-" + strconv.Itoa(len(g.messages)), nil
}

func (g *fakeSDKGateway) StreamSession(_ context.Context, _ sdk.StreamSessionRequest, _ func(sdk.StreamEvent) error) error {
	return nil
}

func (g *fakeSDKGateway) AgentParticipantID() string { return "agent:agent-1" }

func (g *fakeSDKGateway) BridgeParticipantID(platform string) string {
	return sdk.BridgeParticipantID(platform)
}

func (g *fakeSDKGateway) messageCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.messages)
}

// fakeSDKAccountStore is an in-memory AccountStore.
type fakeSDKAccountStore struct {
	mu     sync.Mutex
	states map[string]map[string]any
}

func newFakeSDKAccountStore() *fakeSDKAccountStore {
	return &fakeSDKAccountStore{states: make(map[string]map[string]any)}
}

func (s *fakeSDKAccountStore) SaveChannelAccountState(_ context.Context, accountUUID string, state map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make(map[string]any, len(state))
	for key, value := range state {
		copied[key] = value
	}
	s.states[accountUUID] = copied
	return nil
}

func (s *fakeSDKAccountStore) LoadChannelAccountState(_ context.Context, accountUUID string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[accountUUID]
	copied := make(map[string]any, len(state))
	for key, value := range state {
		copied[key] = value
	}
	return copied, nil
}

type testRoundTripFunc func(*http.Request) (*http.Response, error)

func (f testRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// testJSONResponse builds a 200 response whose body is the JSON encoding of v.
func testJSONResponse(v any) (*http.Response, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(data))),
	}, nil
}

// httpClientReturning returns an *http.Client whose transport answers every
// request with the given JSON value.
func httpClientReturning(v any) *http.Client {
	return &http.Client{Transport: testRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return testJSONResponse(v)
	})}
}

// teamsActivity is a builder for an inbound Bot Framework activity.
type teamsActivity struct {
	Type             string
	ID               string
	ServiceURL       string
	Text             string
	ConversationID   string
	ConversationType string
	TenantID         string
	FromID           string
	FromAADObjectID  string
	RecipientID      string
	MentionBotID     string // when set, adds a mention entity for this id
}

// activityBody marshals the activity into the JSON envelope HandleWebhook parses.
func activityBody(a teamsActivity) []byte {
	env := map[string]any{
		"type":       a.Type,
		"id":         a.ID,
		"serviceUrl": a.ServiceURL,
		"text":       a.Text,
		"conversation": map[string]any{
			"id":               a.ConversationID,
			"conversationType": a.ConversationType,
			"tenantId":         a.TenantID,
		},
		"from": map[string]any{
			"id":          a.FromID,
			"aadObjectId": a.FromAADObjectID,
		},
		"recipient": map[string]any{
			"id": a.RecipientID,
		},
	}
	if a.MentionBotID != "" {
		mention, _ := json.Marshal(map[string]any{
			"type":      "mention",
			"mentioned": map[string]any{"id": a.MentionBotID},
		})
		env["entities"] = []json.RawMessage{mention}
	}
	out, _ := json.Marshal(env)
	return out
}

// teamsAccount builds an account whose credential carries the bot identity.
func teamsAccount(uuid, botID string) sdk.ChannelAccount {
	return sdk.ChannelAccount{
		UUID:     uuid,
		Platform: Platform,
		Credential: map[string]any{
			"account_id":    botID,
			"bot_id":        botID,
			"client_id":     botID,
			"client_secret": "test-secret",
		},
		State: map[string]any{
			"bot_id": botID,
		},
	}
}

func makeRuntime(gw sdk.Gateway, store sdk.AccountStore, accounts ...sdk.ChannelAccount) sdk.Runtime {
	rt := sdk.Runtime{
		WorkspaceUUID: "ws-1",
		Channel:       sdk.Channel{UUID: "channel-1", Platform: Platform},
		Gateway:       gw,
		AccountStore:  store,
	}
	if len(accounts) > 0 {
		rt.Account = accounts[0]
		rt.Accounts = accounts
	}
	return rt
}
