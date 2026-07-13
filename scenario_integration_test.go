package beakteams

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
)

// TestScenario_DirectAndGroupDoNotShareSession: the same account receiving a
// personal (direct) activity and a channel (group) activity must get distinct
// sessions.
func TestScenario_DirectAndGroupDoNotShareSession(t *testing.T) {
	c := Connector{}
	gw := &fakeSDKGateway{}
	store := newFakeSDKAccountStore()
	account := teamsAccount("acct-1", "bot-1")
	rt := makeRuntime(gw, store)

	direct, err := c.HandleWebhook(context.Background(), rt, account, activityBody(teamsActivity{
		Type: "message", ID: "m1", ServiceURL: testServiceURL, Text: "hi",
		ConversationID: "D1", ConversationType: "personal", FromID: "U_HUMAN",
	}))
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	group, err := c.HandleWebhook(context.Background(), rt, account, activityBody(teamsActivity{
		Type: "message", ID: "m2", ServiceURL: testServiceURL, Text: "hi",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	}))
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	if direct.SessionUUID == "" || group.SessionUUID == "" {
		t.Fatalf("missing session uuids: %q %q", direct.SessionUUID, group.SessionUUID)
	}
	if direct.SessionUUID == group.SessionUUID {
		t.Fatalf("direct and group must not share session: %q", direct.SessionUUID)
	}
}

// TestScenario_TwoAccountsSameGroupDoNotShareSession guards the core contract:
// session identity includes the account uuid, so two bots in the same group
// must not share a Beak session.
func TestScenario_TwoAccountsSameGroupDoNotShareSession(t *testing.T) {
	c := Connector{}
	gw := &fakeSDKGateway{}
	store := newFakeSDKAccountStore()

	body := activityBody(teamsActivity{
		Type: "message", ID: "m3", ServiceURL: testServiceURL, Text: "hello team",
		ConversationID: "C_SHARED", ConversationType: "channel", FromID: "U_HUMAN",
	})

	resA, err := c.HandleWebhook(context.Background(), makeRuntime(gw, store), teamsAccount("acct-A", "bot-A"), body)
	if err != nil {
		t.Fatalf("account A: %v", err)
	}
	resB, err := c.HandleWebhook(context.Background(), makeRuntime(gw, store), teamsAccount("acct-B", "bot-B"), body)
	if err != nil {
		t.Fatalf("account B: %v", err)
	}
	if resA.SessionUUID == "" || resB.SessionUUID == "" {
		t.Fatalf("missing session uuids: %q %q", resA.SessionUUID, resB.SessionUUID)
	}
	if resA.SessionUUID == resB.SessionUUID {
		t.Fatalf("two accounts in the same group must not share session: %q", resA.SessionUUID)
	}
}

// TestScenario_DuplicateEventNotDuplicated: replaying the same activity must be
// ignored and must not create a second Beak message.
func TestScenario_DuplicateEventNotDuplicated(t *testing.T) {
	c := Connector{}
	gw := &fakeSDKGateway{}
	store := newFakeSDKAccountStore()
	account := teamsAccount("acct-1", "bot-1")
	rt := makeRuntime(gw, store)

	body := activityBody(teamsActivity{
		Type: "message", ID: "dup-1", ServiceURL: testServiceURL, Text: "once",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})

	first, err := c.HandleWebhook(context.Background(), rt, account, body)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.Ignored {
		t.Fatalf("first delivery must not be ignored")
	}
	second, err := c.HandleWebhook(context.Background(), rt, account, body)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Ignored || second.Reason != "duplicate" {
		t.Fatalf("second delivery must be ignored as duplicate, got ignored=%v reason=%q", second.Ignored, second.Reason)
	}
	if got := gw.messageCount(); got != 1 {
		t.Fatalf("expected exactly 1 message created, got %d", got)
	}
}

// TestScenario_MarkdownOutboundSentOrDegraded: a markdown outbound message is
// delivered (after a conversation reference is captured) and returns the
// platform message id.
func TestScenario_MarkdownOutboundSentOrDegraded(t *testing.T) {
	c := Connector{}
	gw := &fakeSDKGateway{}
	store := newFakeSDKAccountStore()
	account := teamsAccount("acct-1", "bot-1")
	rt := makeRuntime(gw, store, account)
	rt.HTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/oauth2/v2.0/token") {
			return testJSONResponse(map[string]any{"access_token": "tok", "expires_in": 3600})
		}
		return testJSONResponse(map[string]any{"id": "act-md"})
	})}

	// Capture the conversation reference so a proactive send is possible.
	if _, err := c.HandleWebhook(context.Background(), rt, account, activityBody(teamsActivity{
		Type: "message", ID: "seed", ServiceURL: testServiceURL, Text: "seed",
		ConversationID: "C1", ConversationType: "channel", FromID: "U_HUMAN",
	})); err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	res, err := c.Send(context.Background(), rt, sdk.OutboundMessage{
		AccountUUID: "acct-1",
		ChatID:      "C1",
		Text:        "*bold* message",
		Format:      "markdown",
	})
	if err != nil {
		t.Fatalf("send markdown: %v", err)
	}
	if res.MessageID == "" {
		t.Fatalf("expected a message id from the activities POST")
	}
}
