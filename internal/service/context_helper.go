package service

import (
	"context"
	"strconv"

	"google.golang.org/grpc/metadata"
)

// getTenantID extracts the tenant id injected by admin-service as gRPC metadata.
func getTenantID(ctx context.Context) uint32 {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0
	}
	vals := md.Get("x-md-global-tenantid")
	if len(vals) == 0 {
		return 0
	}
	id, _ := strconv.ParseUint(vals[0], 10, 32)
	return uint32(id)
}

func getUserID(ctx context.Context) uint32 {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0
	}
	vals := md.Get("x-md-global-userid")
	if len(vals) == 0 {
		return 0
	}
	id, _ := strconv.ParseUint(vals[0], 10, 32)
	return uint32(id)
}
