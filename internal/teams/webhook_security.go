package teams

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultOpenIDConfigURL is the Bot Framework OpenID configuration document.
	// It points at the JWKS used to sign inbound activity tokens.
	DefaultOpenIDConfigURL = "https://login.botframework.com/v1/.well-known/openidconfiguration"

	// botFrameworkIssuer is the expected "iss" claim on inbound activity tokens.
	botFrameworkIssuer = "https://api.botframework.com"

	// jwksCacheTTL is how long fetched signing keys are cached. Microsoft
	// guidance is to cache for at least 24h and refresh on a cache miss.
	jwksCacheTTL = 24 * time.Hour

	// clockSkew is the tolerance applied to exp/nbf checks.
	clockSkew = 5 * time.Minute

	tokenFetchTimeout = 15 * time.Second
)

// jwksProvider fetches and caches the Bot Framework signing keys. It uses the
// injected *http.Client so tests can stub the OpenID config + JWKS fetches via
// a RoundTripper and never touch the network. A cache miss (unknown kid) or an
// expired cache triggers a refresh; offline/HTTP failures surface as Go errors
// (never a panic).
type jwksProvider struct {
	httpClient      *http.Client
	openIDConfigURL string

	mu        sync.Mutex
	keys      map[string]signingKey
	fetchedAt time.Time
	cacheTTL  time.Duration
}

type signingKey struct {
	publicKey    *rsa.PublicKey
	endorsements []string
}

var sharedJWKSProviders sync.Map

// NewJWKSProvider builds a provider backed by the given HTTP client. A nil
// client falls back to http.DefaultClient.
func NewJWKSProvider(httpClient *http.Client) *jwksProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &jwksProvider{
		httpClient:      httpClient,
		openIDConfigURL: DefaultOpenIDConfigURL,
		keys:            make(map[string]signingKey),
		cacheTTL:        jwksCacheTTL,
	}
}

// SharedJWKSProvider returns one cache per HTTP client so Microsoft signing
// keys are reused across webhook deliveries for the documented 24-hour TTL.
func SharedJWKSProvider(httpClient *http.Client) *jwksProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if provider, ok := sharedJWKSProviders.Load(httpClient); ok {
		return provider.(*jwksProvider)
	}
	provider := NewJWKSProvider(httpClient)
	actual, _ := sharedJWKSProviders.LoadOrStore(httpClient, provider)
	return actual.(*jwksProvider)
}

// keyFor returns the RSA public key whose kid matches. It serves from cache
// when the cache is fresh and contains the kid; otherwise it refreshes the key
// set from the OpenID config -> jwks_uri chain and retries once.
func (p *jwksProvider) keyFor(ctx context.Context, kid string) (signingKey, error) {
	if strings.TrimSpace(kid) == "" {
		return signingKey{}, fmt.Errorf("teams jwt: token has no kid")
	}

	p.mu.Lock()
	fresh := !p.fetchedAt.IsZero() && time.Since(p.fetchedAt) < p.cacheTTL
	if fresh {
		if key, ok := p.keys[kid]; ok {
			p.mu.Unlock()
			return key, nil
		}
	}
	p.mu.Unlock()

	// Cache miss or stale: refresh.
	keys, err := p.fetchKeys(ctx)
	if err != nil {
		return signingKey{}, err
	}
	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = time.Now().UTC()
	key, ok := p.keys[kid]
	p.mu.Unlock()
	if !ok {
		return signingKey{}, fmt.Errorf("teams jwt: no signing key for kid %q", kid)
	}
	return key, nil
}

// fetchKeys performs the OpenID config -> jwks_uri -> JWKS fetch and parses each
// RSA key into an *rsa.PublicKey keyed by kid.
func (p *jwksProvider) fetchKeys(ctx context.Context) (map[string]signingKey, error) {
	var cfg openIDConfig
	if err := p.getJSON(ctx, p.openIDConfigURL, &cfg); err != nil {
		return nil, fmt.Errorf("teams jwks: fetch openid config: %w", err)
	}
	if strings.TrimSpace(cfg.JWKSURI) == "" {
		return nil, fmt.Errorf("teams jwks: openid config has no jwks_uri")
	}

	var set jwks
	if err := p.getJSON(ctx, cfg.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("teams jwks: fetch keys: %w", err)
	}

	out := make(map[string]signingKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "" && !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		if k.Use != "" && !strings.EqualFold(k.Use, "sig") {
			continue
		}
		if k.N == "" || k.E == "" || k.Kid == "" {
			continue
		}
		key, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		out[k.Kid] = signingKey{publicKey: key, endorsements: append([]string(nil), k.Endorsements...)}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("teams jwks: no usable RSA signing keys")
	}
	return out, nil
}

func (p *jwksProvider) getJSON(ctx context.Context, url string, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, tokenFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s failed: status=%d", url, resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// parseRSAPublicKey builds an *rsa.PublicKey from the base64url-encoded modulus
// (n) and exponent (e) carried in a JWK.
func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, fmt.Errorf("invalid exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// jwtHeader is the decoded JOSE header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jwtClaims is the subset of registered/Bot-Framework claims we validate.
type jwtClaims struct {
	Iss        string `json:"iss"`
	Aud        string `json:"aud"`
	Exp        int64  `json:"exp"`
	Nbf        int64  `json:"nbf"`
	ServiceURL string `json:"serviceurl"`
}

// VerifyWebhookToken validates the Authorization Bearer JWT on an inbound Bot
// Framework activity. It enforces alg=RS256, iss/aud, the validity window (with
// ±5m clock skew), the required serviceurl claim against the activity's
// serviceUrl, and the RS256 signature against the JWKS key matching the token
// kid. Any failure is returned as a Go error so the caller can reject with 403.
func VerifyWebhookToken(ctx context.Context, provider *jwksProvider, authorizationHeader, expectedAudience, serviceURL, channelID string, now time.Time) error {
	if provider == nil {
		return fmt.Errorf("teams jwt: provider is required")
	}
	raw := strings.TrimSpace(authorizationHeader)
	if raw == "" {
		return fmt.Errorf("teams jwt: missing Authorization header")
	}
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return fmt.Errorf("teams jwt: Authorization scheme must be Bearer")
	}
	raw = strings.TrimSpace(raw[len("bearer "):])
	if raw == "" {
		return fmt.Errorf("teams jwt: bearer token is empty")
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("teams jwt: malformed token")
	}
	headerSeg, claimSeg, sigSeg := parts[0], parts[1], parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		return fmt.Errorf("teams jwt: decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("teams jwt: parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("teams jwt: unexpected alg %q", header.Alg)
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(claimSeg)
	if err != nil {
		return fmt.Errorf("teams jwt: decode claims: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return fmt.Errorf("teams jwt: parse claims: %w", err)
	}

	if claims.Iss != botFrameworkIssuer {
		return fmt.Errorf("teams jwt: unexpected issuer %q", claims.Iss)
	}
	if strings.TrimSpace(expectedAudience) == "" {
		return fmt.Errorf("teams jwt: expected audience is required")
	}
	if claims.Aud != expectedAudience {
		return fmt.Errorf("teams jwt: audience mismatch")
	}
	if claims.Exp == 0 {
		return fmt.Errorf("teams jwt: exp claim is required")
	}
	if now.After(time.Unix(claims.Exp, 0).Add(clockSkew)) {
		return fmt.Errorf("teams jwt: token expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-clockSkew)) {
		return fmt.Errorf("teams jwt: token not yet valid")
	}
	if strings.TrimSpace(claims.ServiceURL) == "" {
		return fmt.Errorf("teams jwt: serviceurl claim is required")
	}
	if strings.TrimSpace(serviceURL) == "" {
		return fmt.Errorf("teams jwt: activity serviceUrl is required")
	}
	if claims.ServiceURL != serviceURL {
		return fmt.Errorf("teams jwt: serviceurl claim mismatch")
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigSeg)
	if err != nil {
		return fmt.Errorf("teams jwt: decode signature: %w", err)
	}

	key, err := provider.keyFor(ctx, header.Kid)
	if err != nil {
		return err
	}
	if channelID = strings.TrimSpace(channelID); channelID != "" && !containsFold(key.endorsements, channelID) {
		return fmt.Errorf("teams jwt: signing key is not endorsed for channel %q", channelID)
	}

	signingInput := headerSeg + "." + claimSeg
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key.publicKey, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("teams jwt: signature verification failed: %w", err)
	}
	return nil
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}
