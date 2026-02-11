package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"github.com/vibast-solutions/ms-go-auth/app/service"
)

const (
	ContextKeyCallerService   = "caller_service"
	ContextKeyCallerAccessMap = "caller_allowed_access"
)

type APIKeyMiddleware struct {
	authService service.InternalAuthService
}

func NewAPIKeyMiddleware(authService service.InternalAuthService) *APIKeyMiddleware {
	return &APIKeyMiddleware{authService: authService}
}

func (m *APIKeyMiddleware) RequireAPIKey(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Let CORS preflight pass.
		if c.Request().Method == http.MethodOptions {
			return next(c)
		}

		apiKey := strings.TrimSpace(c.Request().Header.Get("X-API-Key"))
		if apiKey == "" {
			logrus.Debug("Missing x-api-key header")
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "unauthorized",
			})
		}

		result, err := m.authService.ValidateInternalAPIKey(c.Request().Context(), apiKey)
		if err != nil {
			if errors.Is(err, service.ErrInvalidInternalAPIKey) {
				logrus.Debug("Invalid x-api-key header")
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "unauthorized",
				})
			}
			logrus.WithError(err).Error("API key validation failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "internal server error",
			})
		}

		c.Set(ContextKeyCallerService, result.GetServiceName())
		c.Set(ContextKeyCallerAccessMap, result.GetAllowedAccess())
		return next(c)
	}
}
