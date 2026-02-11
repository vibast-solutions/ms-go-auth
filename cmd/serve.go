package cmd

import (
	"database/sql"
	"net"

	"github.com/vibast-solutions/ms-go-auth/app/controller"
	authgrpc "github.com/vibast-solutions/ms-go-auth/app/grpc"
	"github.com/vibast-solutions/ms-go-auth/app/middleware"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"
	"github.com/vibast-solutions/ms-go-auth/config"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP and gRPC servers",
	Long:  `Start both HTTP (Echo) and gRPC servers for the authentication service.`,
	Run:   runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) {
	cfg, err := config.Load()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}
	if err := configureLogging(cfg); err != nil {
		logrus.WithError(err).Fatal("Failed to configure logging")
	}

	db, err := sql.Open("mysql", cfg.MySQL.DSN)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logrus.WithError(err).Fatal("Failed to ping database")
	}

	userRepo := repository.NewUserRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(db)
	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	userAuthService := service.NewUserAuthService(db, userRepo, refreshTokenRepo, cfg)
	internalAuthService := service.NewInternalAuthService(internalAPIKeyRepo)

	go startGRPCServer(cfg, userAuthService, internalAuthService)

	startHTTPServer(cfg, userAuthService, internalAuthService)
}

func startHTTPServer(cfg *config.Config, userAuthService service.UserAuthService, internalAuthService service.InternalAuthService) {
	e := echo.New()
	defer e.Close()
	e.HideBanner = true

	e.Use(echomiddleware.RequestLoggerWithConfig(echomiddleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogRemoteIP:  true,
		LogLatency:   true,
		LogUserAgent: true,
		LogError:     true,
		HandleError:  true,
		LogValuesFunc: func(c echo.Context, v echomiddleware.RequestLoggerValues) error {
			fields := logrus.Fields{
				"remote_ip":  v.RemoteIP,
				"host":       v.Host,
				"method":     v.Method,
				"uri":        v.URI,
				"status":     v.Status,
				"latency":    v.Latency.String(),
				"latency_ns": v.Latency.Nanoseconds(),
				"user_agent": v.UserAgent,
			}
			entry := logrus.WithFields(fields)
			if v.Error != nil {
				entry = entry.WithError(v.Error)
			}
			entry.Info("http_request")
			return nil
		},
	}))
	e.Use(echomiddleware.Recover())
	e.Use(echomiddleware.CORS())

	userAuthController := controller.NewUserAuthController(userAuthService)
	internalAuthController := controller.NewInternalAuthController(internalAuthService)
	authMiddleware := middleware.NewAuthMiddleware(userAuthService)
	apiKeyMiddleware := middleware.NewAPIKeyMiddleware(internalAuthService)

	e.Use(apiKeyMiddleware.RequireAPIKey)

	auth := e.Group("/auth")
	auth.POST("/register", userAuthController.Register)
	auth.POST("/login", userAuthController.Login)
	auth.POST("/confirm-account", userAuthController.ConfirmAccount)
	auth.POST("/request-password-reset", userAuthController.RequestPasswordReset)
	auth.POST("/reset-password", userAuthController.ResetPassword)
	auth.POST("/refresh-token", userAuthController.RefreshToken)
	auth.POST("/generate-confirm-token", userAuthController.GenerateConfirmToken)
	auth.POST("/validate-token", userAuthController.ValidateToken)
	auth.POST("/internal/access", internalAuthController.InternalAccess)

	authProtected := auth.Group("")
	authProtected.Use(authMiddleware.RequireAuth)
	authProtected.POST("/logout", userAuthController.Logout)
	authProtected.POST("/change-password", userAuthController.ChangePassword)

	httpAddr := net.JoinHostPort(cfg.HTTP.Host, cfg.HTTP.Port)
	logrus.WithField("addr", httpAddr).Info("Starting HTTP server")
	if err := e.Start(httpAddr); err != nil {
		logrus.WithError(err).Fatal("Failed to start HTTP server")
	}
}

func startGRPCServer(cfg *config.Config, userAuthService service.UserAuthService, internalAuthService service.InternalAuthService) {
	grpcAddr := net.JoinHostPort(cfg.GRPC.Host, cfg.GRPC.Port)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to listen on gRPC port")
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authgrpc.APIKeyUnaryInterceptor(internalAuthService)),
		grpc.StreamInterceptor(authgrpc.APIKeyStreamInterceptor(internalAuthService)),
	)
	defer grpcServer.GracefulStop()
	authServer := authgrpc.NewAuthServer(userAuthService, internalAuthService)
	types.RegisterAuthServiceServer(grpcServer, authServer)

	logrus.WithField("addr", grpcAddr).Info("Starting gRPC server")
	if err := grpcServer.Serve(lis); err != nil {
		logrus.WithError(err).Fatal("Failed to start gRPC server")
	}
	logrus.Info("gRPC server started")
}
