// Package openapi embeds the DNS browser API contract.
package openapi

import _ "embed"

// DNS is the OpenAPI 3.1 document served and validated by the service.
//
//go:embed dns.yaml
var DNS []byte
