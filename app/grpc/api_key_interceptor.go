package grpc

import (
	"context"
	"errors"
	"strings"

	"github.com/vibast-solutions/ms-go-auth/app/dto"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type callerServiceKey struct{}
type callerAllowedAccessKey struct{}

func APIKeyUnaryInterceptor(authService *service.AuthService) gogrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *gogrpc.UnaryServerInfo, handler gogrpc.UnaryHandler) (any, error) {
		result, err := validateIncomingAPIKey(ctx, authService)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, callerServiceKey{}, result.ServiceName)
		ctx = context.WithValue(ctx, callerAllowedAccessKey{}, result.AllowedAccess)
		return handler(ctx, req)
	}
}

func APIKeyStreamInterceptor(authService *service.AuthService) gogrpc.StreamServerInterceptor {
	return func(srv any, ss gogrpc.ServerStream, _ *gogrpc.StreamServerInfo, handler gogrpc.StreamHandler) error {
		result, err := validateIncomingAPIKey(ss.Context(), authService)
		if err != nil {
			return err
		}

		ctx := context.WithValue(ss.Context(), callerServiceKey{}, result.ServiceName)
		ctx = context.WithValue(ctx, callerAllowedAccessKey{}, result.AllowedAccess)
		return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
	}
}

func validateIncomingAPIKey(ctx context.Context, authService *service.AuthService) (*dto.InternalAccessResult, error) {
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
