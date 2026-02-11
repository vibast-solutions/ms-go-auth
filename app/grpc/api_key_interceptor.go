package grpc

import (
	"context"
	"errors"
	"strings"

	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type callerServiceKey struct{}
type callerAllowedAccessKey struct{}

func APIKeyUnaryInterceptor(authService service.InternalAuthService) gogrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *gogrpc.UnaryServerInfo, handler gogrpc.UnaryHandler) (any, error) {
		result, err := validateIncomingAPIKey(ctx, authService)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, callerServiceKey{}, result.GetServiceName())
		ctx = context.WithValue(ctx, callerAllowedAccessKey{}, result.GetAllowedAccess())
		return handler(ctx, req)
	}
}

func APIKeyStreamInterceptor(authService service.InternalAuthService) gogrpc.StreamServerInterceptor {
	return func(srv any, ss gogrpc.ServerStream, _ *gogrpc.StreamServerInfo, handler gogrpc.StreamHandler) error {
		result, err := validateIncomingAPIKey(ss.Context(), authService)
		if err != nil {
			return err
		}

		ctx := context.WithValue(ss.Context(), callerServiceKey{}, result.GetServiceName())
		ctx = context.WithValue(ctx, callerAllowedAccessKey{}, result.GetAllowedAccess())
		return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
	}
}

func validateIncomingAPIKey(ctx context.Context, authService service.InternalAuthService) (*types.ValidateInternalAccessResponse, error) {
	apiKey := incomingAPIKeyFromMetadata(ctx)
	if apiKey == "" {
		return nil, status.Error(codes.Unauthenticated, "unauthorized")
	}

	result, err := authService.ValidateInternalAPIKey(ctx, apiKey)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInternalAPIKey) {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return result, nil
}

func incomingAPIKeyFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("x-api-key")
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

type wrappedServerStream struct {
	gogrpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
