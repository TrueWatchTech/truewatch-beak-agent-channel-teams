package teams

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testKID         = "test-kid"
	testAudience    = "test-client-id"
	testServiceURL  = "https://smba.trafficmanager.net/amer/"
	sentinelConfig  = "https://sentinel.local/openid-config"
	sentinelJWKSURI = "https://sentinel.local/keys"
)

// jwtFixture bundles a signing key and a RoundTripper that serves the matching
// OpenID config + JWKS, counting HTTP fetches so cache reuse can be asserted.
type jwtFixture struct {
	key   *rsa.PrivateKey
	kid   string
	hits  *int
	trans http.RoundTripper
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newJWTFixture builds an RSA key and a transport publishing it under kid.
func newJWTFixture(t *testing.T, kid string) *jwtFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
	jwksDoc := map[string]any{
		"keys": []map[string]any{{
			"kty":          "RSA",
			"kid":          kid,
			"use":          "sig",
			"n":            b64url(key.PublicKey.N.Bytes()),
			"e":            b64url(eBytes),
			"endorsements": []string{"msteams"},
		}},
	}
	hits := 0
	trans := testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		hits++
		switch req.URL.String() {
		case sentinelConfig:
			return jwtJSON(map[string]any{"jwks_uri": sentinelJWKSURI})
		case sentinelJWKSURI:
			return jwtJSON(jwksDoc)
		}
		t.Fatalf("unexpected fetch: %s", req.URL.String())
		return nil, nil
	})
	return &jwtFixture{key: key, kid: kid, hits: &hits, trans: trans}
}

func jwtJSON(v any) (*http.Response, error) {
	data, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(data))),
	}, nil
}

func (f *jwtFixture) provider() *jwksProvider {
	p := NewJWKSProvider(&http.Client{Transport: f.trans})
	p.openIDConfigURL = sentinelConfig
	return p
}

// signToken builds a signed RS256 JWT with the given kid and claims.
func (f *jwtFixture) signToken(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64url(hb) + "." + b64url(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":        "https://api.botframework.com",
		"aud":        testAudience,
		"exp":        now.Add(time.Hour).Unix(),
		"nbf":        now.Add(-time.Minute).Unix(),
		"serviceurl": testServiceURL,
	}
}

func TestVerifyWebhookToken_Valid(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	tok := f.signToken(t, testKID, validClaims(now))
	err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "msteams", now)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestVerifyWebhookToken_TamperedSignature(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	tok := f.signToken(t, testKID, validClaims(now))
	// Mutate the FIRST byte of the signature segment. Flipping the last base64
	// char can be a no-op (for a 256-byte signature the final char's low bits are
	// unused), so tamper a high-order char to guarantee the decoded sig changes.
	dot := strings.LastIndex(tok, ".")
	sig := tok[dot+1:]
	first := "A"
	if sig[0] == 'A' {
		first = "B"
	}
	tampered := tok[:dot+1] + first + sig[1:]
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tampered, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected tampered signature to be rejected")
	}
}

func TestVerifyWebhookToken_Expired(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	claims := validClaims(now)
	claims["exp"] = now.Add(-time.Hour).Unix()
	tok := f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestVerifyWebhookToken_UnknownKid(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	// Sign with a kid the JWKS does not publish.
	tok := f.signToken(t, "other-kid", validClaims(now))
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected unknown kid to be rejected")
	}
}

func TestVerifyWebhookToken_WrongAudience(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	claims := validClaims(now)
	claims["aud"] = "some-other-app"
	tok := f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
}

func TestVerifyWebhookToken_WrongIssuer(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	claims := validClaims(now)
	claims["iss"] = "https://evil.example.com"
	tok := f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected issuer mismatch to be rejected")
	}
}

func TestVerifyWebhookToken_CacheReused(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	p := f.provider()

	tok1 := f.signToken(t, testKID, validClaims(now))
	if err := VerifyWebhookToken(context.Background(), p, "Bearer "+tok1, testAudience, testServiceURL, "", now); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	afterFirst := *f.hits
	if afterFirst == 0 {
		t.Fatal("expected the first verify to fetch the key set")
	}

	tok2 := f.signToken(t, testKID, validClaims(now))
	if err := VerifyWebhookToken(context.Background(), p, "Bearer "+tok2, testAudience, testServiceURL, "", now); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if *f.hits != afterFirst {
		t.Fatalf("expected cache reuse (no refetch); hits went %d -> %d", afterFirst, *f.hits)
	}
}

func TestSharedJWKSProvider_ReusesProviderForHTTPClient(t *testing.T) {
	client := &http.Client{Transport: testRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})}
	if first, second := SharedJWKSProvider(client), SharedJWKSProvider(client); first != second {
		t.Fatal("expected the JWKS provider cache to be shared for one HTTP client")
	}
}

func TestVerifyWebhookToken_RequiresBearerSchemeAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	claims := validClaims(now)
	tok := f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected a token without Bearer scheme to be rejected")
	}
	delete(claims, "exp")
	tok = f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "", now); err == nil {
		t.Fatal("expected a token without exp to be rejected")
	}
}

func TestVerifyWebhookToken_RequiresChannelEndorsement(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)
	tok := f.signToken(t, testKID, validClaims(now))
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "webchat", now); err == nil {
		t.Fatal("expected mismatched channel endorsement to be rejected")
	}
}

func TestVerifyWebhookToken_RequiresMatchingServiceURL(t *testing.T) {
	now := time.Now().UTC()
	f := newJWTFixture(t, testKID)

	claims := validClaims(now)
	delete(claims, "serviceurl")
	tok := f.signToken(t, testKID, claims)
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, testServiceURL, "msteams", now); err == nil {
		t.Fatal("expected a token without serviceurl to be rejected")
	}

	tok = f.signToken(t, testKID, validClaims(now))
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, "", "msteams", now); err == nil {
		t.Fatal("expected an activity without serviceUrl to be rejected")
	}
	if err := VerifyWebhookToken(context.Background(), f.provider(), "Bearer "+tok, testAudience, "https://smba.trafficmanager.net/emea/", "msteams", now); err == nil {
		t.Fatal("expected a mismatched activity serviceUrl to be rejected")
	}
}
