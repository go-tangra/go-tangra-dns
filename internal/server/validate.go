package server

import (
	"context"

	"buf.build/go/protovalidate"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"google.golang.org/protobuf/proto"
)

// protoValidator validates requests using bufbuild/protovalidate, which reads
// buf.validate annotations at runtime via reflection (no code generation).
func protoValidator() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if msg, ok := req.(proto.Message); ok {
				if err := protovalidate.Validate(msg); err != nil {
					return nil, errors.BadRequest("VALIDATOR", err.Error())
				}
			}
			return handler(ctx, req)
		}
	}
}
