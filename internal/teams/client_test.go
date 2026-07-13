package teams

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TrueWatchTech/truewatch-beak-agent-channel-teams/sdk"
)

type testRoundTripFunc func(*http.Request) (*http.Response, error)

func (f testRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// jsonResp builds a 200 response with a JSON body from v.
func jsonResp(v any) (*http.Response, error) {
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

func TestClientValidate(t *testing.T) {
	var sawValidate bool
	httpClient := &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/botframework.com/oauth2/v2.0/token" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		sawValidate = true
		return jsonResp(map[string]any{"access_token": "x", "token_type": "Bearer", "expires_in": 3600})
	})}

	client := NewClient("", map[string]string{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
	})
	client.HTTPClient = httpClient

	info, err := client.Validate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sawValidate {
		t.Fatal("validate endpoint was not called")
	}
	if info.AccountID != "test-client-id" || info.BotID != "test-client-id" {
		t.Fatalf("unexpected bot info: %#v", info)
	}
}

func TestClientValidate_InvalidToken(t *testing.T) {
	httpClient := &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(map[string]any{"error": "invalid_client", "error_description": "bad secret"})
	})}
	client := NewClient("", map[string]string{"client_id": "c", "client_secret": "bad"})
	client.HTTPClient = httpClient

	if _, err := client.Validate(context.Background()); err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestClientSendText(t *testing.T) {
	var sawActivities bool
	var sawAuth string
	httpClient := &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/oauth2/v2.0/token") {
			return jsonResp(map[string]any{"access_token": "tok", "expires_in": 3600})
		}
		if strings.Contains(req.URL.Path, "/v3/conversations/") && strings.HasSuffix(req.URL.Path, "/activities") {
			sawActivities = true
			sawAuth = req.Header.Get("Authorization")
			return jsonResp(map[string]any{"id": "act-9"})
		}
		t.Fatalf("unexpected path %q", req.URL.Path)
		return nil, nil
	})}
	client := NewClient("", map[string]string{"client_id": "c", "client_secret": "s"})
	client.HTTPClient = httpClient

	id, err := client.SendText(context.Background(), "https://smba.trafficmanager.net/amer/", "C1", "", "hi", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if id != "act-9" {
		t.Fatalf("id=%q want act-9", id)
	}
	if !sawActivities {
		t.Fatal("activities endpoint was not called")
	}
	if sawAuth != "Bearer tok" {
		t.Fatalf("missing/incorrect bearer token: %q", sawAuth)
	}
}

func TestValidateServiceURL_RejectsNonAllowlisted(t *testing.T) {
	if err := validateServiceURL("https://evil.example.com/"); err == nil {
		t.Fatal("expected non-allowlisted host to be rejected")
	}
	if err := validateServiceURL("http://smba.trafficmanager.net/x"); err == nil {
		t.Fatal("expected non-https to be rejected")
	}
	if err := validateServiceURL("https://smba.trafficmanager.net/x"); err != nil {
		t.Fatalf("allowlisted host rejected: %v", err)
	}
	if err := validateServiceURL("https://amer.botframework.com/x"); err != nil {
		t.Fatalf("botframework.com subdomain rejected: %v", err)
	}
}

func TestBuildMentionEntities_DoesNotDuplicateExistingMarkup(t *testing.T) {
	prefix, entities := buildMentionEntities("<at>Alice</at> hello", []sdk.MentionIdentity{{ID: "29:alice", DisplayName: "Alice"}})
	if prefix != "" {
		t.Fatalf("existing mention markup must not be prepended again: %q", prefix)
	}
	if len(entities) != 1 {
		t.Fatalf("mention entity must still be emitted: %#v", entities)
	}
}

func TestMentionAllRequiresExplicitAllIdentity(t *testing.T) {
	if hasMentionAllIdentity([]sdk.MentionIdentity{{ID: "29:alice", DisplayName: "Alice"}}) {
		t.Fatal("an ordinary user mention must not satisfy mention_all")
	}
	if !hasMentionAllIdentity([]sdk.MentionIdentity{{ID: "19:channel", IDType: "teams_mention_all", DisplayName: "Everyone"}}) {
		t.Fatal("an explicit Teams all identity should satisfy mention_all")
	}
}
