package pdns

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// ListSupermasters returns all supermaster entries.
func (c *Client) ListSupermasters(ctx context.Context) ([]Supermaster, error) {
	var out []Supermaster
	if err := c.do(ctx, http.MethodGet, c.supermastersURL(), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSupermaster adds a (ip, nameserver, account) entry.
func (c *Client) CreateSupermaster(ctx context.Context, sm *Supermaster) error {
	return c.do(ctx, http.MethodPost, c.supermastersURL(), sm, nil)
}

// DeleteSupermaster removes the entry matched by (ip, nameserver).
func (c *Client) DeleteSupermaster(ctx context.Context, ip, nameserver string) error {
	path := c.supermastersURL() + "/" + ip + "/" + nameserver
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func readAllString(r io.Reader) (string, error) {
	var sb strings.Builder
	if _, err := io.Copy(&sb, r); err != nil {
		return "", err
	}
	return sb.String(), nil
}
