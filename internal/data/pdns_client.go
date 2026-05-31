package data

import (
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/pdns"
)

// NewPdnsClient builds a PowerDNS API client from environment variables.
//
//	PDNS_API_URL    base URL, e.g. "http://powerdns:8081"  (default)
//	PDNS_API_KEY    api-key from pdns.conf                (required)
//	PDNS_SERVER_ID  PowerDNS server id                    (default "localhost")
func NewPdnsClient(ctx *bootstrap.Context) *pdns.Client {
	l := ctx.NewLoggerHelper("dns/pdns")

	endpoint := getEnvOrDefault("PDNS_API_URL", "http://powerdns:8081")
	apiKey := getEnvOrDefault("PDNS_API_KEY", "")
	serverID := getEnvOrDefault("PDNS_SERVER_ID", "localhost")

	if apiKey == "" {
		l.Warn("PDNS_API_KEY not set — calls to PowerDNS will fail with 401")
	}
	l.Infof("PowerDNS API endpoint: %s (server=%s)", endpoint, serverID)

	return pdns.NewClient(endpoint, apiKey, serverID)
}
