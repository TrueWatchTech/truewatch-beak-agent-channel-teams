package teams

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var (
	ErrCredentialRejected = errors.New("teams credential rejected")
	ErrTransientFailure   = errors.New("teams transient platform failure")
)

type HTTPError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s failed: status=%d body=%s", e.Method, e.Path, e.StatusCode, e.Body)
}

func credentialRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrCredentialRejected, message)
}

func transientFailure(message string) error {
	return fmt.Errorf("%w: %s", ErrTransientFailure, message)
}

func transientFailureWithCause(message string, cause error) error {
	if cause == nil {
		return transientFailure(message)
	}
	return fmt.Errorf("%w: %s: %w", ErrTransientFailure, message, cause)
}

func oauthCredentialRejected(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_client", "unauthorized_client", "invalid_grant", "invalid_scope":
		return true
	default:
		return false
	}
}

func oauthTransientFailure(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "server_error", "temporarily_unavailable":
		return true
	default:
		return false
	}
}

func IsCredentialRejected(err error) bool {
	if errors.Is(err, ErrCredentialRejected) {
		return true
	}
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden)
}

func IsRetryableError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, ErrTransientFailure) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusRequestTimeout || httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= http.StatusInternalServerError)
}
