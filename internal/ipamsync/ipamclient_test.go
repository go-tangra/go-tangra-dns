package ipamsync

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/services/ipam/pkg/ipamclient"
)

type stubReader struct{ err error }

func (s stubReader) GetAddress(_ context.Context, _, id string) (ipamclient.IPAddress, error) {
	if s.err != nil {
		return ipamclient.IPAddress{}, s.err
	}
	return ipamclient.IPAddress{ID: id, Address: "192.0.2.1", SubnetID: "s", Hostname: "h.example.com", MACAddress: "aa"}, nil
}

func (s stubReader) GetSubnet(_ context.Context, _, id string) (ipamclient.Subnet, error) {
	if s.err != nil {
		return ipamclient.Subnet{}, s.err
	}
	return ipamclient.Subnet{ID: id, CIDR: "192.0.2.0/24"}, nil
}

func TestClientAdapter(t *testing.T) {
	ctx := context.Background()
	c := Client{R: stubReader{}}
	a, err := c.GetAddress(ctx, "t", "a1")
	if err != nil || a != (Address{ID: "a1", Address: "192.0.2.1", SubnetID: "s", Hostname: "h.example.com"}) {
		t.Fatalf("address = %+v %v", a, err)
	}
	sn, err := c.GetSubnet(ctx, "t", "s")
	if err != nil || sn.CIDR != "192.0.2.0/24" {
		t.Fatalf("subnet = %+v %v", sn, err)
	}
	c = Client{R: stubReader{err: status.Error(codes.NotFound, "not_found")}}
	if _, err := c.GetAddress(ctx, "t", "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not found = %v", err)
	}
	c = Client{R: stubReader{err: status.Error(codes.Unavailable, "down")}}
	if _, err := c.GetAddress(ctx, "t", "a1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unavailable = %v", err)
	}
	if _, err := c.GetSubnet(ctx, "t", "s"); err == nil {
		t.Fatal("subnet error swallowed")
	}
}
