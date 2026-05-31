// Package pdns is an HTTP client for the PowerDNS Authoritative Server REST API.
//
// API reference: https://doc.powerdns.com/authoritative/http-api/
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	apiHeader      = "X-API-Key"
	defaultTimeout = 10 * time.Second
)

// ErrNotFound is returned when the PowerDNS API responds with 404.
var ErrNotFound = errors.New("pdns: not found")

// Client wraps the PowerDNS API.
type Client struct {
	endpoint   string
	apiKey     string
	serverID   string
	httpClient *http.Client
}

// NewClient builds a PowerDNS API client.
//
// endpoint should be the base URL, e.g. "http://powerdns:8081".
// apiKey is the value of the api-key= setting in pdns.conf.
// serverID is the PowerDNS server identifier (almost always "localhost").
func NewClient(endpoint, apiKey, serverID string) *Client {
	if serverID == "" {
		serverID = "localhost"
	}
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		serverID: serverID,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// apiError is the error envelope returned by PowerDNS.
type apiError struct {
	Error string `json:"error"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("pdns: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	url := c.endpoint + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("pdns: build request: %w", err)
	}
	req.Header.Set(apiHeader, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pdns: http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		_ = json.Unmarshal(respBody, &ae)
		if ae.Error != "" {
			return fmt.Errorf("pdns: %d %s: %s", resp.StatusCode, resp.Status, ae.Error)
		}
		return fmt.Errorf("pdns: %d %s: %s", resp.StatusCode, resp.Status, string(respBody))
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("pdns: decode response: %w", err)
	}
	return nil
}

func (c *Client) zonesURL() string {
	return fmt.Sprintf("/api/v1/servers/%s/zones", c.serverID)
}

func (c *Client) zoneURL(id string) string {
	return fmt.Sprintf("%s/%s", c.zonesURL(), id)
}

func (c *Client) supermastersURL() string {
	return fmt.Sprintf("/api/v1/servers/%s/supermasters", c.serverID)
}
