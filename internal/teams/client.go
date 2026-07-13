package teams

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TrueWatch/beak-agent-channel-teams/sdk"
)

// DefaultBaseURL is the Microsoft Teams API base. Override via NewClient for private
// deployments or tests; do not surface it in CredentialSchema.
const DefaultBaseURL = "https://login.microsoftonline.com"

const defaultRequestTimeout = 15 * time.Second

// Client is the Microsoft Teams HTTP client. Credentials are kept in a map so the
// scaffold stays platform-agnostic; read them with stringValue helpers in the
// methods you implement.
//
// Credential fields supplied by CredentialSchema:
//   - client_id: Microsoft App ID (Client ID)
//   - client_secret: Client Secret (App Password)
//   - tenant_id: Tenant ID (optional)
type Client struct {
	BaseURL        string
	Credential     map[string]string
	RequestTimeout time.Duration
	HTTPClient     *http.Client

	// tokenMu guards the cached app token. The Bot Framework access token
	// (expires_in ~3600s) is cached on the client for the lifetime of an
	// outbound request batch; it is never written back to the credential.
	tokenMu      sync.Mutex
	cachedToken  string
	tokenExpires time.Time
}

func NewClient(baseURL string, credential map[string]string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	if credential == nil {
		credential = make(map[string]string)
	}
	return &Client{
		BaseURL:        baseURL,
		Credential:     credential,
		RequestTimeout: defaultRequestTimeout,
		HTTPClient:     http.DefaultClient,
	}
}

// botFrameworkScope is the OAuth2 scope required to call the Bot Connector API.
const botFrameworkScope = "https://api.botframework.com/.default"

// tokenPath returns the token endpoint path. Multi-tenant bots use the
// botframework.com tenant; single-tenant bots use their directory tenant id.
func (c *Client) tokenPath() string {
	if tenant := strings.TrimSpace(c.Credential["tenant_id"]); tenant != "" {
		return "/" + tenant + "/oauth2/v2.0/token"
	}
	return "/botframework.com/oauth2/v2.0/token"
}

// Validate proves the app registration is valid by acquiring a Bot Framework
// token via the client_credentials grant. There is no "get bot info" call for
// Bot Framework, so a successful token IS the validation. The normalized
// identity is the app (client) id. HTTP/parse failures and an error response
// (bad client_secret, unknown client_id) are returned as Go errors; the
// connector maps them to Valid=false.
func (c *Client) Validate(ctx context.Context) (*BotInfo, error) {
	clientID := strings.TrimSpace(c.Credential["client_id"])
	if clientID == "" {
		return nil, fmt.Errorf("teams client_id is required")
	}
	if _, err := c.acquireToken(ctx); err != nil {
		return nil, err
	}
	return &BotInfo{
		AccountID:   clientID,
		BotID:       clientID,
		DisplayName: clientID,
		BotName:     clientID,
	}, nil
}

// AppToken returns a valid Bot Framework access token, acquiring a fresh one via
// client_credentials when the cached token is missing or near expiry.
func (c *Client) AppToken(ctx context.Context) (string, error) {
	return c.acquireToken(ctx)
}

func (c *Client) acquireToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	if c.cachedToken != "" && time.Now().UTC().Before(c.tokenExpires) {
		token := c.cachedToken
		c.tokenMu.Unlock()
		return token, nil
	}
	c.tokenMu.Unlock()

	clientID := strings.TrimSpace(c.Credential["client_id"])
	clientSecret := strings.TrimSpace(c.Credential["client_secret"])
	if clientID == "" {
		return "", fmt.Errorf("teams client_id is required")
	}
	if clientSecret == "" {
		return "", fmt.Errorf("teams client_secret is required")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", botFrameworkScope)

	var resp tokenResponse
	if err := c.doForm(ctx, c.tokenPath(), form, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" || resp.AccessToken == "" {
		msg := resp.ErrorDescription
		if msg == "" {
			msg = resp.Error
		}
		if msg == "" {
			msg = "token acquisition failed"
		}
		return "", fmt.Errorf("teams token: %s", msg)
	}

	expiresIn := resp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	c.tokenMu.Lock()
	c.cachedToken = resp.AccessToken
	// Refresh 60s before the real expiry to avoid using a token that lapses
	// mid-request.
	c.tokenExpires = time.Now().UTC().Add(time.Duration(expiresIn-60) * time.Second)
	c.tokenMu.Unlock()
	return resp.AccessToken, nil
}

// SendText acquires an app token and posts a message Activity to
// {serviceURL}/v3/conversations/{chatID}/activities, returning the created
// activity id. serviceURL must come from a previously stored conversation
// reference; it is validated against the Microsoft service-url allowlist to
// prevent SSRF. markdown is delivered with textFormat=markdown.
func (c *Client) SendText(ctx context.Context, serviceURL, chatID, text, format string, mentions []sdk.MentionIdentity, mentionAll bool) (string, error) {
	if strings.TrimSpace(serviceURL) == "" {
		return "", fmt.Errorf("teams serviceUrl is required")
	}
	if strings.TrimSpace(chatID) == "" {
		return "", fmt.Errorf("teams chat_id is required")
	}
	if err := validateServiceURL(serviceURL); err != nil {
		return "", err
	}
	token, err := c.acquireToken(ctx)
	if err != nil {
		return "", err
	}

	textFormat := "plain"
	if strings.EqualFold(format, "markdown") {
		textFormat = "markdown"
	}
	_ = mentions
	_ = mentionAll

	payload := map[string]any{
		"type":       "message",
		"text":       text,
		"textFormat": textFormat,
	}

	base := strings.TrimRight(serviceURL, "/")
	endpoint := base + "/v3/conversations/" + url.PathEscape(chatID) + "/activities"

	var resp sendActivityResponse
	if err := c.doJSONAbsolute(ctx, http.MethodPost, endpoint, payload, &resp, withBearer(token)); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// validateServiceURL enforces an allowlist of known Microsoft connector-service
// hosts so a forged inbound activity cannot point outbound traffic at an
// arbitrary host (SSRF).
func validateServiceURL(serviceURL string) error {
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		return fmt.Errorf("teams serviceUrl is invalid: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("teams serviceUrl must be https")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "smba.trafficmanager.net" ||
		strings.HasSuffix(host, ".botframework.com") ||
		host == "botframework.com" {
		return nil
	}
	return fmt.Errorf("teams serviceUrl host %q is not an allowed Bot Framework endpoint", host)
}

// doForm POSTs an application/x-www-form-urlencoded body (relative to BaseURL)
// and decodes the JSON response into out. The OAuth2 token endpoint requires
// form encoding rather than the JSON used elsewhere.
func (c *Client) doForm(ctx context.Context, path string, form url.Values, out any) error {
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.url(path, nil), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "BeakAgentTeams/0.1.0")
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		// Decode regardless of status so the caller can surface the OAuth2
		// error/error_description on a non-2xx response.
		_ = json.Unmarshal(data, out)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s failed: status=%d body=%s", path, resp.StatusCode, string(data))
	}
	return nil
}

// doJSONAbsolute is like doJSON but takes a fully-qualified URL (used for
// outbound activities posted to the dynamic per-tenant serviceUrl).
func (c *Client) doJSONAbsolute(ctx context.Context, method, fullURL string, body any, out any, opts ...requestOption) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, fullURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "BeakAgentTeams/0.1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for _, opt := range opts {
		opt(req)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s failed: status=%d body=%s", method, fullURL, resp.StatusCode, string(data))
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

type requestOption func(*http.Request)

func withBearer(token string) requestOption {
	return func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func (c *Client) url(path string, query map[string]string) string {
	base := strings.TrimRight(c.BaseURL, "/")
	values := url.Values{}
	for key, value := range query {
		if value != "" {
			values.Set(key, value)
		}
	}
	out := base + "/" + strings.TrimLeft(path, "/")
	if encoded := values.Encode(); encoded != "" {
		out += "?" + encoded
	}
	return out
}
