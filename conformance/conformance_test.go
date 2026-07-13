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
		CredentialCases:          conformance.MustLoadJSON[[]conformance.CredentialValidationCase](t, "testdata/beak-conformance/credential_cases.json"),
		InboundCases:             conformance.MustLoadJSON[[]conformance.InboundCase](t, "testdata/beak-conformance/inbound_cases.json"),
	})
}
