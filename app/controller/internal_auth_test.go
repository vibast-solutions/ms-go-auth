package controller_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
)

func TestInternalAccess_MissingBodyAPIKey(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/internal/access", map[string]string{})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.InternalAccess(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestInternalAccess_InvalidAPIKey(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/internal/access", map[string]string{
		"api_key": "invalid-key",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns))

	if err := controllerWithMock.InternalAccess(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestInternalAccess_Success(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	now := time.Now()
	req, rec := newJSONRequest(t, http.MethodPost, "/auth/internal/access", map[string]string{
		"api_key": "valid-key",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).AddRow(
			uint64(1),
			"profile-service",
			"hash",
			`["notifications","auth"]`,
			true,
			now.Add(time.Hour),
			now,
			now,
		))

	if err := controllerWithMock.InternalAccess(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"service_name":"profile-service"`) {
		t.Fatalf("expected service_name in response, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"allowed_access":["notifications","auth"]`) {
		t.Fatalf("expected allowed_access in response, got %s", rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
