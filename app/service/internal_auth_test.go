package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/vibast-solutions/ms-go-auth/app/service"
)

func TestInternalAuthService_ValidateInternalAPIKey_Success(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	rawKey := "msint_test_key"
	keyHash := hashInternalAPIKeyForTest(rawKey)
	now := time.Now()

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(keyHash).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).AddRow(
			uint64(1),
			"profile-service",
			keyHash,
			`["notifications","auth"]`,
			true,
			now.Add(time.Hour),
			now,
			now,
		))

	res, err := svc.ValidateInternalAPIKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("validate internal api key failed: %v", err)
	}
	if res.ServiceName != "profile-service" {
		t.Fatalf("expected service_name profile-service, got %q", res.ServiceName)
	}
	if len(res.AllowedAccess) != 2 {
		t.Fatalf("expected 2 allowed access entries, got %#v", res.AllowedAccess)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestInternalAuthService_GenerateInternalAPIKey_FailsWhenActiveExists(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(findInternalByServiceName).
		WithArgs("profile-service", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).AddRow(
			uint64(1),
			"profile-service",
			"existing-hash",
			`[]`,
			true,
			now.Add(time.Hour),
			now,
			now,
		))

	_, err := svc.GenerateInternalAPIKey(context.Background(), "profile-service")
	if err == nil || !errors.Is(err, service.ErrServiceHasActiveAPIKey) {
		t.Fatalf("expected ErrServiceHasActiveAPIKey, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestInternalAuthService_AddInternalAllowedAccess_UpdatesMissingEntries(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(findInternalByServiceName).
		WithArgs("profile-service", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).
			AddRow(
				uint64(2),
				"profile-service",
				"hash-2",
				`[]`,
				true,
				now.Add(time.Hour),
				now,
				now,
			).
			AddRow(
				uint64(1),
				"profile-service",
				"hash-1",
				`["notifications"]`,
				true,
				now.Add(time.Hour),
				now,
				now,
			))

	mock.ExpectExec(updateInternalAPIKeyQuery).
		WithArgs(
			"profile-service",
			"hash-2",
			`["notifications"]`,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.AddInternalAllowedAccess(context.Background(), "profile-service", "notifications"); err != nil {
		t.Fatalf("add internal allowed access failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestInternalAuthService_RegenerateInternalAPIKey_Success(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(findInternalByServiceName).
		WithArgs("profile-service", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).
			AddRow(
				uint64(2),
				"profile-service",
				"hash-2",
				`["svc-b","svc-c"]`,
				true,
				now.Add(time.Hour),
				now,
				now,
			).
			AddRow(
				uint64(1),
				"profile-service",
				"hash-1",
				`["svc-a","svc-b"]`,
				true,
				now.Add(2*time.Hour),
				now,
				now,
			))

	mock.ExpectExec(updateInternalAPIKeyQuery).
		WithArgs(
			"profile-service",
			"hash-2",
			`["svc-b","svc-c"]`,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(updateInternalAPIKeyQuery).
		WithArgs(
			"profile-service",
			"hash-1",
			`["svc-a","svc-b"]`,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			uint64(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(insertInternalAPIKeyQuery).
		WithArgs(
			"profile-service",
			sqlmock.AnyArg(),
			`["svc-a","svc-b","svc-c"]`,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(3, 1))

	key, err := svc.RegenerateInternalAPIKey(context.Background(), "profile-service", 10*time.Minute)
	if err != nil {
		t.Fatalf("regenerate internal api key failed: %v", err)
	}
	if key == "" {
		t.Fatalf("expected a new API key")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestInternalAuthService_RegenerateInternalAPIKey_InvalidTTL(t *testing.T) {
	svc, _, cleanup := newServiceWithMock(t)
	defer cleanup()

	_, err := svc.RegenerateInternalAPIKey(context.Background(), "profile-service", 5*time.Minute)
	if err == nil || !errors.Is(err, service.ErrInvalidRegenerationTTL) {
		t.Fatalf("expected ErrInvalidRegenerationTTL, got %v", err)
	}
}
