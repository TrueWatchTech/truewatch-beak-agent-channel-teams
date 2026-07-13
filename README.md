# Microsoft Teams Channel SDK

`github.com/TrueWatchTech/truewatch-beak-agent-channel-teams` connects Microsoft Teams bot accounts to the Beak Channel Gateway. It
implements the common `sdk.Connector` interface plus a teams-specific
inbound entry point.

Platform-specific logic — `Validate`, `SendText`, webhook verification, and
inbound event parsing — is fully implemented. Use `NewConnector()` to obtain a
`sdk.Connector` ready for registration.

## Module

```
github.com/TrueWatchTech/truewatch-beak-agent-channel-teams
```

## Usage

```go
import (
    "fmt"

    beak "github.com/TrueWatchTech/truewatch-beak-agent-channel-teams"
)

func main() {
    connector := beak.NewConnector()
    fmt.Println(connector.Metadata().Label)
}
```

## Credential fields

These are the fields surfaced in the Beak console form (`CredentialSchema`):

| Key | Title | Secret | Required |
| --- | --- | --- | --- |
| `client_id` | Microsoft App ID (Client ID) | no | yes |
| `client_secret` | Client Secret (App Password) | yes | yes |
| `tenant_id` | Tenant ID (optional) | no | no |

Backend-only values (base URL, callback URL, offsets, token cache) are never
exposed in the form.

## Event delivery

Mode: **webhook**

The Beak host owns the HTTP endpoint and forwards the raw request to
`HandleWebhookRequest`, which verifies the signature and parses the event.

## Webhook security

Strategy: **jwt**

Inbound requests must use `Authorization: Bearer <JWT>`. The SDK verifies
RS256 signature, issuer, audience, expiry/not-before, `serviceurl`, and the
activity `channelId` endorsement. Bot Framework OpenID/JWKS documents are
cached per HTTP client for 24 hours.

The runtime bot mention identity comes from `activity.recipient.id` (normally
`28:<MicrosoftAppId>`). The stable Beak account key remains `client_id`.

## Outbound

`Send` maps the common `OutboundMessage` (`Text`, `Format`, `Mentions`,
`MentionAll`, `ThreadID`) onto the Microsoft Teams send endpoint. `ThreadID`
is mapped to a Bot Framework reply activity ID. Mentions are encoded as both
visible `<at>...</at>` text and Bot Framework mention entities. `MentionAll`
requires an explicit Teams mention identity because Teams has no safe generic
ID that the SDK can invent.

Incoming `replyToId` is exposed through both `ThreadID` and
`ReferencedMessage.MessageID`. The Bot Connector API cannot fetch arbitrary
historical activities, so referenced text remains empty and `Raw.fetch_error`
explains that boundary. Adaptive Card text fields are reduced to common inbound
text when the activity has no top-level `text`.

Teams acknowledgement modes are currently not portable through Bot Framework;
`Acknowledge` returns `status=unsupported` rather than requiring Beak to branch
on the platform.

## State

Account-scoped state lives in `state/state.go`. Common collections plus the
platform fields are persisted via `sdk.AccountStore`. Successful webhook
activity processing updates the standard `stream_connection_state`,
`stream_last_activity_at`, and `stream_last_event_at` health keys.

## Verification

```bash
go test ./...
cd conformance && go test ./...
```
