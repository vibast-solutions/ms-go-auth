package controller

import (
	"errors"
	"net/http"

	httpdto "github.com/vibast-solutions/ms-go-auth/app/dto"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type InternalAuthController struct {
	internalAuthService service.InternalAuthService
}

func NewInternalAuthController(internalAuthService service.InternalAuthService) *InternalAuthController {
	return &InternalAuthController{internalAuthService: internalAuthService}
}

func (c *InternalAuthController) InternalAccess(ctx echo.Context) error {
	req, err := types.NewValidateInternalAccessRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind internal access request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	result, err := c.internalAuthService.ValidateInternalAPIKey(ctx.Request().Context(), req.GetApiKey())
	if err != nil {
		if errors.Is(err, service.ErrInvalidInternalAPIKey) {
			return ctx.JSON(http.StatusNotFound, httpdto.ErrorResponse{Error: "api key not found"})
		}
		logrus.WithError(err).Error("Internal access validation failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, result)
}
