package middleware

import (
	"net/http"
	"strings"

	"github.com/vibast-solutions/ms-go-auth/app/service"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type accessTokenValidator interface {
	ValidateAccessToken(tokenString string) (*service.Claims, error)
}

type AuthMiddleware struct {
	authService accessTokenValidator
}

func NewAuthMiddleware(authService accessTokenValidator) *AuthMiddleware {
	return &AuthMiddleware{authService: authService}
}

func (m *AuthMiddleware) RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			logrus.Debug("Missing authorization header")
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "missing authorization header",
			})
		}

		parts := strings.Fields(authHeader)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			logrus.Debug("Invalid authorization header format")
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid authorization header format",
			})
		}

		tokenString := parts[1]
		claims, err := m.authService.ValidateAccessToken(tokenString)
		if err != nil {
			logrus.Debug("Invalid or expired access token")
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired token",
			})
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)

		return next(c)
	}
}
