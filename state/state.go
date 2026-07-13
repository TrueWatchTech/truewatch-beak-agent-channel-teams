package state

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const (
	maxTrackedStateKeys = 4096
	trackedStateTTL     = 7 * 24 * time.Hour
)

type AccountState struct {
	AccountID              string                     `json:"account_id"`
	ChannelLinkSession     string                     `json:"channel_link_session,omitempty"`
	PeerSessions           map[string]string          `json:"peer_sessions,omitempty"`
	InboundSeen            map[string]string          `json:"inbound_seen,omitempty"`
	SentBeakMessages       map[string]string          `json:"sent_beak_messages,omitempty"`
	StreamCursors          map[string]string          `json:"stream_cursors,omitempty"`
	TenantID               string                     `json:"tenant_id,omitempty"`
	BotID                  string                     `json:"bot_id,omitempty"`
	ConversationReferences map[string]json.RawMessage `json:"conversation_references,omitempty"`
	ServiceUrls            map[string]string          `json:"service_urls,omitempty"`
	UpdatedAt              time.Time                  `json:"updated_at"`
}

func (a *AccountState) EnsureMaps() {
	if a == nil {
		return
	}
	if a.PeerSessions == nil {
		a.PeerSessions = make(map[string]string)
	}
	if a.InboundSeen == nil {
		a.InboundSeen = make(map[string]string)
	}
	if a.SentBeakMessages == nil {
		a.SentBeakMessages = make(map[string]string)
	}
	if a.StreamCursors == nil {
		a.StreamCursors = make(map[string]string)
	}
	if a.ConversationReferences == nil {
		a.ConversationReferences = make(map[string]json.RawMessage)
	}
	if a.ServiceUrls == nil {
		a.ServiceUrls = make(map[string]string)
	}
}

func TouchAccount(account *AccountState) error {
	if account == nil {
		return fmt.Errorf("account state is nil")
	}
	if account.AccountID == "" {
		return fmt.Errorf("account_id is required")
	}
	account.EnsureMaps()
	now := time.Now().UTC()
	pruneTimestampMap(account.InboundSeen, now)
	pruneTimestampMap(account.SentBeakMessages, now)
	account.UpdatedAt = now
	return nil
}

func pruneTimestampMap(values map[string]string, now time.Time) {
	for key, raw := range values {
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil && now.Sub(ts) > trackedStateTTL {
			delete(values, key)
		}
	}
	if len(values) <= maxTrackedStateKeys {
		return
	}
	type item struct {
		key string
		at  time.Time
	}
	items := make([]item, 0, len(values))
	for key, raw := range values {
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			ts = time.Time{}
		}
		items = append(items, item{key: key, at: ts})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].at.Before(items[j].at)
	})
	for len(values) > maxTrackedStateKeys && len(items) > 0 {
		delete(values, items[0].key)
		items = items[1:]
	}
}
