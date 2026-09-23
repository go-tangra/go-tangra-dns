package ipamsync

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/services/ipam/pkg/ipamclient"
)

// AddressReader is the part of ipamclient.Client the sync uses.
type AddressReader interface {
	GetAddress(ctx context.Context, tenantID, id string) (ipamclient.IPAddress, error)
	GetSubnet(ctx context.Context, tenantID, id string) (ipamclient.Subnet, error)
}

// Client adapts ipamclient (ipam.v1 over SPIFFE mTLS) to IPAM: a NotFound
// status becomes ErrNotFound (the address was released).
type Client struct{ R AddressReader }

var _ IPAM = Client{}

// GetAddress implements IPAM.
func (c Client) GetAddress(ctx context.Context, tenantID, id string) (Address, error) {
	a, err := c.R.GetAddress(ctx, tenantID, id)
	if status.Code(err) == codes.NotFound {
		return Address{}, ErrNotFound
	}
	if err != nil {
		return Address{}, err
	}
	return Address{ID: a.ID, Address: a.Address, SubnetID: a.SubnetID, Hostname: a.Hostname}, nil
}

// GetSubnet implements IPAM.
func (c Client) GetSubnet(ctx context.Context, tenantID, id string) (Subnet, error) {
	s, err := c.R.GetSubnet(ctx, tenantID, id)
	if err != nil {
		return Subnet{}, err
	}
	return Subnet{ID: s.ID, CIDR: s.CIDR}, nil
}
