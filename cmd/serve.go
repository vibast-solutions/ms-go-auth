package cmd

import (
	"database/sql"
	"fmt"
	"log"
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
		log.Fatalf("Failed to load configuration: %v", err)
	}

	db, err := sql.Open("mysql", cfg.DSN())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
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

	e.Use(echomiddleware.Logger())
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
	log.Printf("Starting HTTP server on %s", httpAddr)
	if err := e.Start(httpAddr); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func startGRPCServer(cfg *config.Config, authService *service.AuthService) {
	grpcAddr := net.JoinHostPort(cfg.GRPCHost, cfg.GRPCPort)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port: %v", err)
	}

	grpcServer := grpc.NewServer()
	defer grpcServer.GracefulStop()
	authServer := authgrpc.NewAuthServer(authService)
	types.RegisterAuthServiceServer(grpcServer, authServer)

	log.Printf("Starting gRPC server on %s", grpcAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
	}
	fmt.Println("gRPC server started")
}
