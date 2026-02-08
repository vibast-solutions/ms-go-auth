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

	db, err := sql.Open("mysql", cfg.DSN())
	if err != nil {
		logrus.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logrus.WithError(err).Fatal("Failed to ping database")
	}

	userRepo := repository.NewUserRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(db)
	authService := service.NewAuthService(db, userRepo, refreshTokenRepo, cfg)

	go startGRPCServer(cfg, authService)

	startHTTPServer(cfg, authService)
}

func startHTTPServer(cfg *config.Config, authService *service.AuthService) {
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

	authController := controller.NewAuthController(authService)
	authMiddleware := middleware.NewAuthMiddleware(authService)

	auth := e.Group("/auth")
	auth.POST("/register", authController.Register)
	auth.POST("/login", authController.Login)
	auth.POST("/confirm-account", authController.ConfirmAccount)
	auth.POST("/request-password-reset", authController.RequestPasswordReset)
	auth.POST("/reset-password", authController.ResetPassword)
	auth.POST("/refresh-token", authController.RefreshToken)
	auth.POST("/generate-confirm-token", authController.GenerateConfirmToken)
	auth.POST("/validate-token", authController.ValidateToken)

	authProtected := auth.Group("")
	authProtected.Use(authMiddleware.RequireAuth)
	authProtected.POST("/logout", authController.Logout)
	authProtected.POST("/change-password", authController.ChangePassword)

	httpAddr := net.JoinHostPort(cfg.HTTPHost, cfg.HTTPPort)
	logrus.WithField("addr", httpAddr).Info("Starting HTTP server")
	if err := e.Start(httpAddr); err != nil {
		logrus.WithError(err).Fatal("Failed to start HTTP server")
	}
}

func startGRPCServer(cfg *config.Config, authService *service.AuthService) {
	grpcAddr := net.JoinHostPort(cfg.GRPCHost, cfg.GRPCPort)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to listen on gRPC port")
	}

	grpcServer := grpc.NewServer()
	defer grpcServer.GracefulStop()
	authServer := authgrpc.NewAuthServer(authService)
	types.RegisterAuthServiceServer(grpcServer, authServer)

	logrus.WithField("addr", grpcAddr).Info("Starting gRPC server")
	if err := grpcServer.Serve(lis); err != nil {
		logrus.WithError(err).Fatal("Failed to start gRPC server")
	}
	logrus.Info("gRPC server started")
}
