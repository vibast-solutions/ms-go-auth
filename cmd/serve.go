package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"net"

	"auth/app/controller"
	authgrpc "auth/app/grpc"
	"auth/app/middleware"
	"auth/app/repository"
	"auth/app/service"
	"auth/app/types"
	"auth/config"

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

func runServe(cmd *cobra.Command, args []string) {
	cfg := config.Load()

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
	authService := service.NewAuthService(userRepo, refreshTokenRepo, cfg)

	go startGRPCServer(cfg, authService)

	startHTTPServer(cfg, authService)
}

func startHTTPServer(cfg *config.Config, authService *service.AuthService) {
	e := echo.New()
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

	log.Printf("Starting HTTP server on :%s", cfg.HTTPPort)
	if err := e.Start(":" + cfg.HTTPPort); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func startGRPCServer(cfg *config.Config, authService *service.AuthService) {
	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port: %v", err)
	}

	grpcServer := grpc.NewServer()
	authServer := authgrpc.NewAuthServer(authService)
	types.RegisterAuthServiceServer(grpcServer, authServer)

	log.Printf("Starting gRPC server on :%s", cfg.GRPCPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
	}
	fmt.Println("gRPC server started")
}
