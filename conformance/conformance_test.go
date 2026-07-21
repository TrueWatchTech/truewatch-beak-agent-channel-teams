package teamsconformance

import (
	"testing"

	conformance "gitlab.jiagouyun.com/guance/beak-agent-channel-sdk/beak-channel-sdk-conformance"
)

func TestConformance(t *testing.T) {
	a := newAdapter()
	conformance.Run(t, conformance.Config{
		Platform:                 "teams",
		MetadataProvider:         a,
		CredentialSchemaProvider: a,
		CredentialValidator:      a,
		InboundParser:            a,
		Acknowledger:             a,
		Sender:                   a,
		CredentialCases:          conformance.MustLoadJSON[[]conformance.CredentialValidationCase](t, "testdata/beak-conformance/credential_cases.json"),
		InboundCases:             conformance.MustLoadJSON[[]conformance.InboundCase](t, "testdata/beak-conformance/inbound_cases.json"),
		AckCases:                 conformance.MustLoadJSON[[]conformance.AckCase](t, "testdata/beak-conformance/ack_cases.json"),
		SendCases: []conformance.SendCase{{
			Name: "text outbound exposes common send result",
			Request: conformance.OutboundMessage{
				AccountUUID: "app-id", ChatType: "group", ChatID: "C1",
				MessageUUID: "message-send-teams", Text: "Teams outbound", Format: "text",
			},
			Expect: conformance.SendExpectation{MessageID: "activity-conformance"},
		}},
	})
}
