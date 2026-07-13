# Microsoft Teams Channel SDK

`github.com/TrueWatch/beak-agent-channel-teams` connects Microsoft Teams bot accounts to the Beak Channel Gateway. It
implements the common `sdk.Connector` interface plus a teams-specific
inbound entry point.

Platform-specific logic — `Validate`, `SendText`, webhook verification, and
inbound event parsing — is fully implemented. Use `NewConnector()` to obtain a
`sdk.Connector` ready for registration.

## Module

```
github.com/TrueWatch/beak-agent-channel-teams
```

## Usage

```go
import (
    "fmt"

    beak "github.com/TrueWatch/beak-agent-channel-teams"
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



## Outbound

`Send` maps the common `OutboundMessage` (`Text`, `Format`, `Mentions`,
`MentionAll`) onto the Microsoft Teams send endpoint (`/v3/conversations/{conversationId}/activities`).

## State

Account-scoped state lives in `state/state.go`. Common collections plus the
platform fields are persisted via `sdk.AccountStore`.
