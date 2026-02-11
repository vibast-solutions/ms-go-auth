package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
)

var apiKeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "Manage internal service API keys",
}

var apiKeyGenerateCmd = &cobra.Command{
	Use:   "generate <service_name>",
	Short: "Generate an internal API key for a service",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		internalAuthService, db, err := newInternalAuthServiceForAPIKeyCommands()
		if err != nil {
			return err
		}
		defer db.Close()

		serviceName := args[0]
		key, err := internalAuthService.GenerateInternalAPIKey(context.Background(), serviceName)
		if err != nil {
			if errors.Is(err, service.ErrServiceHasActiveAPIKey) {
				return fmt.Errorf("service %q already has an active API key", serviceName)
			}
			return err
		}

		fmt.Printf("service_name: %s\n", serviceName)
		fmt.Printf("api_key: %s\n", key)
		fmt.Printf("expires_at: %s\n", time.Now().AddDate(100, 0, 0).Format(time.RFC3339))
		return nil
	},
}

var apiKeyAllowCmd = &cobra.Command{
	Use:   "allow <service_name> <allowed_service>",
	Short: "Allow a service to call another service",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		internalAuthService, db, err := newInternalAuthServiceForAPIKeyCommands()
		if err != nil {
			return err
		}
		defer db.Close()

		serviceName := args[0]
		allowedService := args[1]

		if err = internalAuthService.AddInternalAllowedAccess(context.Background(), serviceName, allowedService); err != nil {
			if errors.Is(err, service.ErrServiceHasNoActiveAPIKey) {
				return fmt.Errorf("service %q has no active API key", serviceName)
			}
			return err
		}

		fmt.Printf("allowed access updated: %s -> %s\n", serviceName, allowedService)
		return nil
	},
}

var apiKeyDeactivateCmd = &cobra.Command{
	Use:   "deactivate <service_name>",
	Short: "Deactivate all active API keys for a service",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		internalAuthService, db, err := newInternalAuthServiceForAPIKeyCommands()
		if err != nil {
			return err
		}
		defer db.Close()

		serviceName := args[0]
		count, err := internalAuthService.DeactivateInternalAPIKeys(context.Background(), serviceName)
		if err != nil {
			if errors.Is(err, service.ErrServiceHasNoActiveAPIKey) {
				return fmt.Errorf("service %q has no active API key", serviceName)
			}
			return err
		}

		fmt.Printf("deactivated %d active API key(s) for service %s\n", count, serviceName)
		return nil
	},
}

var apiKeyRegenerateCmd = &cobra.Command{
	Use:   "regenerate <service_name>",
	Short: "Regenerate an internal API key and expire old active keys after a grace period",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		internalAuthService, db, err := newInternalAuthServiceForAPIKeyCommands()
		if err != nil {
			return err
		}
		defer db.Close()

		serviceName := args[0]
		oldKeyTTL, err := promptOldKeyTTLMinutes()
		if err != nil {
			return err
		}

		newKey, err := internalAuthService.RegenerateInternalAPIKey(context.Background(), serviceName, oldKeyTTL)
		if err != nil {
			if errors.Is(err, service.ErrServiceHasNoActiveAPIKey) {
				return fmt.Errorf("service %q has no active API key", serviceName)
			}
			if errors.Is(err, service.ErrInvalidRegenerationTTL) {
				return fmt.Errorf("old key grace period must be greater than 5 minutes")
			}
			return err
		}

		fmt.Printf("service_name: %s\n", serviceName)
		fmt.Printf("old_key_expires_in_minutes: %d\n", int(oldKeyTTL.Minutes()))
		fmt.Printf("new_api_key: %s\n", newKey)
		fmt.Printf("new_key_expires_at: %s\n", time.Now().AddDate(100, 0, 0).Format(time.RFC3339))
		return nil
	},
}

func init() {
	apiKeyCmd.AddCommand(apiKeyGenerateCmd)
	apiKeyCmd.AddCommand(apiKeyAllowCmd)
	apiKeyCmd.AddCommand(apiKeyDeactivateCmd)
	apiKeyCmd.AddCommand(apiKeyRegenerateCmd)
	rootCmd.AddCommand(apiKeyCmd)
}

func newInternalAuthServiceForAPIKeyCommands() (service.InternalAuthService, *sql.DB, error) {
	_ = godotenv.Load()

	dsn := strings.TrimSpace(os.Getenv("MYSQL_DSN"))
	if dsn == "" {
		return nil, nil, errors.New("MYSQL_DSN environment variable is required")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, nil, err
	}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, nil, err
	}

	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	internalAuthService := service.NewInternalAuthService(internalAPIKeyRepo)

	return internalAuthService, db, nil
}

func promptOldKeyTTLMinutes() (time.Duration, error) {
	const defaultMinutes = 60
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Expire old key in minutes (>5) [%d]: ", defaultMinutes)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return time.Duration(defaultMinutes) * time.Minute, nil
	}

	minutes, err := strconv.Atoi(input)
	if err != nil {
		return 0, errors.New("invalid number of minutes")
	}
	if minutes <= 5 {
		return 0, errors.New("value must be greater than 5 minutes")
	}

	return time.Duration(minutes) * time.Minute, nil
}
