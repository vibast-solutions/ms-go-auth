package grpc_test

import (
	"context"
	"testing"
	"time"

	authgrpc "github.com/vibast-solutions/ms-go-auth/app/grpc"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var interceptorInternalAPIKeyColumns = []string{
	"id",
	"service_name",
	"key_hash",
	"allowed_access_json",
	"is_active",
	"expires_at",
	"created_at",
	"updated_at",
}

const interceptorFindInternalByHashQuery = `(?s)SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+FROM internal_api_keys\s+WHERE key_hash = \? AND is_active = 1 AND expires_at > NOW\(\)\s+ORDER BY id DESC\s+LIMIT 1`

func newServiceForInterceptor(t *testing.T) (service.InternalAuthService, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	internalAuthService := service.NewInternalAuthService(internalAPIKeyRepo)

	return internalAuthService, mock, func() { _ = db.Close() }
}

func TestAPIKeyUnaryInterceptor_MissingKey(t *testing.T) {
	authService, _, cleanup := newServiceForInterceptor(t)
	defer cleanup()

	interceptor := authgrpc.APIKeyUnaryInterceptor(authService)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func TestAPIKeyUnaryInterceptor_InvalidKey(t *testing.T) {
	authService, mock, cleanup := newServiceForInterceptor(t)
	defer cleanup()

	mock.ExpectQuery(interceptorFindInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(interceptorInternalAPIKeyColumns))

	interceptor := authgrpc.APIKeyUnaryInterceptor(authService)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "invalid"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAPIKeyUnaryInterceptor_ValidKey(t *testing.T) {
	authService, mock, cleanup := newServiceForInterceptor(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(interceptorFindInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(interceptorInternalAPIKeyColumns).AddRow(
			uint64(1),
			"profile-service",
			"hash",
			`["auth"]`,
			true,
			now.Add(time.Hour),
			now,
			now,
		))

	interceptor := authgrpc.APIKeyUnaryInterceptor(authService)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "valid"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAPIKeyUnaryInterceptor_InternalError(t *testing.T) {
	authService, mock, cleanup := newServiceForInterceptor(t)
	defer cleanup()

	mock.ExpectQuery(interceptorFindInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(status.Error(codes.Internal, "db down"))

	interceptor := authgrpc.APIKeyUnaryInterceptor(authService)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "valid"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected internal, got %v", err)
	}
}
