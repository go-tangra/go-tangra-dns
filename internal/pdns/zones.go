package pdns

import (
	"context"
	"net/http"
)

// ListZones returns all zones from PowerDNS.
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var zones []Zone
	if err := c.do(ctx, http.MethodGet, c.zonesURL(), nil, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// GetZone returns a single zone with its RRsets.
func (c *Client) GetZone(ctx context.Context, id string) (*Zone, error) {
	var z Zone
	if err := c.do(ctx, http.MethodGet, c.zoneURL(id), nil, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// CreateZone creates a new zone in PowerDNS.
func (c *Client) CreateZone(ctx context.Context, z *Zone) (*Zone, error) {
	var out Zone
	if err := c.do(ctx, http.MethodPost, c.zonesURL(), z, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateZoneMetadata updates zone-level fields (kind, masters, dnssec, ...).
// Uses PUT which PowerDNS treats as metadata-only updates.
func (c *Client) UpdateZoneMetadata(ctx context.Context, id string, z *Zone) error {
	return c.do(ctx, http.MethodPut, c.zoneURL(id), z, nil)
}

// DeleteZone removes a zone from PowerDNS.
func (c *Client) DeleteZone(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, c.zoneURL(id), nil, nil)
}

// PatchRRsets applies a batch of REPLACE/DELETE changes to a zone's RRsets.
func (c *Client) PatchRRsets(ctx context.Context, id string, rrsets []RRset) error {
	return c.do(ctx, http.MethodPatch, c.zoneURL(id), &RRsetsPatch{RRsets: rrsets}, nil)
}

// NotifyZone sends a NOTIFY to all SLAVE servers for the zone.
func (c *Client) NotifyZone(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPut, c.zoneURL(id)+"/notify", nil, nil)
}

// ExportZone returns the zone contents in BIND text format.
// PowerDNS exposes /export as text/plain rather than JSON.
func (c *Client) ExportZone(ctx context.Context, id string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+c.zoneURL(id)+"/export", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(apiHeader, c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := readAllString(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return "", &APIError{Status: resp.StatusCode, Body: body}
	}
	return body, nil
}

// APIError is a transport-level error returned when PowerDNS replies non-2xx.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return "pdns api error: " + e.Body
}
