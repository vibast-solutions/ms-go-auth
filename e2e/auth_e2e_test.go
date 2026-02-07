//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"auth/app/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultHTTPBase = "http://localhost:8080"
	defaultGRPCAddr = "localhost:9090"
)

type httpClient struct {
	baseURL string
	client  *http.Client
}

func newHTTPClient() *httpClient {
	base := os.Getenv("AUTH_HTTP_URL")
	if base == "" {
		base = defaultHTTPBase
	}
	return &httpClient{
		baseURL: base,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *httpClient) postJSON(t *testing.T, path string, body any) (*http.Response, []byte) {
	t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioReadAll(resp)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	return resp, bodyBytes
}

func waitForHTTP(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/auth/validate-token", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("http service not ready at %s", baseURL)
}

func waitForGRPC(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("grpc service not ready at %s", addr)
}

func TestAuthE2E_HTTPFlow(t *testing.T) {
	httpBase := os.Getenv("AUTH_HTTP_URL")
	if httpBase == "" {
		httpBase = defaultHTTPBase
	}
	grpcAddr := os.Getenv("AUTH_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = defaultGRPCAddr
	}

	if err := waitForHTTP(httpBase, 30*time.Second); err != nil {
		t.Fatalf("http not ready: %v", err)
	}
	if err := waitForGRPC(grpcAddr, 30*time.Second); err != nil {
		t.Fatalf("grpc not ready: %v", err)
	}

	client := newHTTPClient()

	state := struct {
		email           string
		password        string
		newPassword     string
		confirmToken    string
		accessToken     string
		refreshToken    string
		newRefreshToken string
		accessToken2    string
		refreshToken2   string
		resetToken      string
	}{
		email:       fmt.Sprintf("e2e+%d@example.com", time.Now().UnixNano()),
		password:    "StrongPass1!",
		newPassword: "NewStrongPass1!",
	}

	abort := false
	fail := func(t *testing.T, format string, args ...any) {
		abort = true
		t.Fatalf(format, args...)
	}

	step := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			if abort {
				t.Skip("previous step failed")
			}
			fn(t)
		})
	}

	step("LoginBeforeRegister", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected login before register to fail, got %d", resp.StatusCode)
		}
	})

	step("Register", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/register", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusCreated {
			fail(t, "register status: %d body: %s", resp.StatusCode, string(body))
		}

		var regRes struct {
			ConfirmToken string `json:"confirm_token"`
		}
		if err := json.Unmarshal(body, &regRes); err != nil {
			fail(t, "register unmarshal failed: %v", err)
		}
		if regRes.ConfirmToken == "" {
			fail(t, "expected confirm_token")
		}
		state.confirmToken = regRes.ConfirmToken
	})

	step("RegisterWeakPassword", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/register", map[string]string{
			"email":    "weak-" + state.email,
			"password": "short",
		})
		if resp.StatusCode != http.StatusBadRequest {
			fail(t, "expected weak password register to fail, got %d", resp.StatusCode)
		}
	})

	step("RegisterDuplicate", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/register", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusConflict {
			fail(t, "expected duplicate register conflict, got %d", resp.StatusCode)
		}
	})

	step("LoginBeforeConfirm", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusForbidden {
			fail(t, "expected login before confirm to fail, got %d", resp.StatusCode)
		}
	})

	step("GenerateConfirmToken", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/generate-confirm-token", map[string]string{
			"email": state.email,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "generate confirm token status: %d body: %s", resp.StatusCode, string(body))
		}
		var genRes struct {
			ConfirmToken string `json:"confirm_token"`
		}
		if err := json.Unmarshal(body, &genRes); err != nil {
			fail(t, "generate confirm token unmarshal failed: %v", err)
		}
		if genRes.ConfirmToken == "" {
			fail(t, "expected confirm token from generate-confirm-token")
		}
	})

	step("ConfirmAccount", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/confirm-account", map[string]string{
			"token": state.confirmToken,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "confirm status: %d body: %s", resp.StatusCode, string(body))
		}
	})

	step("GenerateConfirmTokenAfterConfirm", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/generate-confirm-token", map[string]string{
			"email": state.email,
		})
		if resp.StatusCode != http.StatusBadRequest {
			fail(t, "expected generate confirm token after confirmation to fail, got %d", resp.StatusCode)
		}
	})

	step("Login", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "login status: %d body: %s", resp.StatusCode, string(body))
		}

		var loginRes struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &loginRes); err != nil {
			fail(t, "login unmarshal failed: %v", err)
		}
		if loginRes.AccessToken == "" || loginRes.RefreshToken == "" {
			fail(t, "expected access and refresh tokens")
		}
		state.accessToken = loginRes.AccessToken
		state.refreshToken = loginRes.RefreshToken
	})

	step("ValidateToken", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/validate-token", map[string]string{
			"access_token": state.accessToken,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "validate status: %d body: %s", resp.StatusCode, string(body))
		}
		if !bytes.Contains(body, []byte(`"valid":true`)) {
			fail(t, "expected valid=true, got %s", string(body))
		}
	})

	step("ValidateTokenInvalid", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/validate-token", map[string]string{
			"access_token": "invalid-token",
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "validate invalid status: %d body: %s", resp.StatusCode, string(body))
		}
		if !bytes.Contains(body, []byte(`"valid":false`)) {
			fail(t, "expected valid=false, got %s", string(body))
		}
	})

	step("RefreshToken", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/refresh-token", map[string]string{
			"refresh_token": state.refreshToken,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "refresh status: %d body: %s", resp.StatusCode, string(body))
		}
		var refreshRes struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &refreshRes); err != nil {
			fail(t, "refresh unmarshal failed: %v", err)
		}
		if refreshRes.RefreshToken == "" {
			fail(t, "expected new refresh token")
		}
		state.newRefreshToken = refreshRes.RefreshToken
	})

	step("RefreshTokenConcurrent", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "login for concurrency test status: %d body: %s", resp.StatusCode, string(body))
		}
		var concLogin struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &concLogin); err != nil {
			fail(t, "login for concurrency unmarshal failed: %v", err)
		}
		var wg sync.WaitGroup
		results := make(chan int, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, _ := client.postJSON(t, "/auth/refresh-token", map[string]string{
					"refresh_token": concLogin.RefreshToken,
				})
				results <- r.StatusCode
			}()
		}
		wg.Wait()
		close(results)
		var okCount, unauthorizedCount int
		for code := range results {
			if code == http.StatusOK {
				okCount++
			} else if code == http.StatusUnauthorized {
				unauthorizedCount++
			}
		}
		if okCount != 1 || unauthorizedCount != 1 {
			fail(t, "expected one success and one unauthorized, got ok=%d unauthorized=%d", okCount, unauthorizedCount)
		}
	})

	step("OldRefreshTokenInvalid", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/refresh-token", map[string]string{
			"refresh_token": state.refreshToken,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected old refresh token invalid, got %d", resp.StatusCode)
		}
	})

	step("InvalidRefreshToken", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/refresh-token", map[string]string{
			"refresh_token": "invalid",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected invalid refresh token to fail, got %d", resp.StatusCode)
		}
	})

	step("ChangePassword", func(t *testing.T) {
		reqBody := map[string]string{
			"old_password": state.password,
			"new_password": state.newPassword,
		}
		resp, body := client.postJSONWithAuth(t, "/auth/change-password", state.accessToken, reqBody)
		if resp.StatusCode != http.StatusOK {
			fail(t, "change password status: %d body: %s", resp.StatusCode, string(body))
		}
	})

	step("ChangePasswordWeak", func(t *testing.T) {
		resp, _ := client.postJSONWithAuth(t, "/auth/change-password", state.accessToken, map[string]string{
			"old_password": state.newPassword,
			"new_password": "short",
		})
		if resp.StatusCode != http.StatusBadRequest {
			fail(t, "expected weak new password to fail, got %d", resp.StatusCode)
		}
	})

	step("ChangePasswordInvalidToken", func(t *testing.T) {
		reqBody := map[string]string{
			"old_password": state.password,
			"new_password": state.newPassword,
		}
		resp, _ := client.postJSONWithAuth(t, "/auth/change-password", "invalid", reqBody)
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected change password with invalid token to fail, got %d", resp.StatusCode)
		}
	})

	step("Logout", func(t *testing.T) {
		resp, body := client.postJSONWithAuth(t, "/auth/logout", state.accessToken, map[string]string{
			"refresh_token": state.newRefreshToken,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "logout status: %d body: %s", resp.StatusCode, string(body))
		}
	})

	step("LogoutInvalidatesRefresh", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/refresh-token", map[string]string{
			"refresh_token": state.newRefreshToken,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected refresh token invalid after logout, got %d", resp.StatusCode)
		}
	})

	step("LoginOldPasswordFails", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			fail(t, "expected old password to fail, got %d", resp.StatusCode)
		}
	})

	step("LoginNewPassword", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.newPassword,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "login with new password status: %d body: %s", resp.StatusCode, string(body))
		}
		var loginRes2 struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &loginRes2); err != nil {
			fail(t, "login2 unmarshal failed: %v", err)
		}
		state.accessToken2 = loginRes2.AccessToken
		state.refreshToken2 = loginRes2.RefreshToken
	})

	step("RequestResetUnknownUser", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/request-password-reset", map[string]string{
			"email": "missing-" + state.email,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "expected reset request for missing user to return 200, got %d", resp.StatusCode)
		}
	})

	step("RequestReset", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/request-password-reset", map[string]string{
			"email": state.email,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "request reset status: %d body: %s", resp.StatusCode, string(body))
		}
		var resetReqRes struct {
			ResetToken string `json:"reset_token"`
		}
		if err := json.Unmarshal(body, &resetReqRes); err != nil {
			fail(t, "reset request unmarshal failed: %v", err)
		}
		if resetReqRes.ResetToken == "" {
			fail(t, "expected reset token")
		}
		state.resetToken = resetReqRes.ResetToken
	})

	step("ResetWeakPassword", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/reset-password", map[string]string{
			"token":        state.resetToken,
			"new_password": "short",
		})
		if resp.StatusCode != http.StatusBadRequest {
			fail(t, "expected weak reset password to fail, got %d", resp.StatusCode)
		}
	})

	step("ResetPassword", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/reset-password", map[string]string{
			"token":        state.resetToken,
			"new_password": state.password,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "reset password status: %d body: %s", resp.StatusCode, string(body))
		}
	})

	step("ResetPasswordUsedToken", func(t *testing.T) {
		resp, _ := client.postJSON(t, "/auth/reset-password", map[string]string{
			"token":        state.resetToken,
			"new_password": state.password,
		})
		if resp.StatusCode != http.StatusBadRequest {
			fail(t, "expected reset with used token to fail, got %d", resp.StatusCode)
		}
	})

	step("LoginAfterReset", func(t *testing.T) {
		resp, body := client.postJSON(t, "/auth/login", map[string]string{
			"email":    state.email,
			"password": state.password,
		})
		if resp.StatusCode != http.StatusOK {
			fail(t, "login after reset status: %d body: %s", resp.StatusCode, string(body))
		}
	})

	step("GRPCValidateToken", func(t *testing.T) {
		conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fail(t, "grpc new client failed: %v", err)
		}
		defer conn.Close()

		grpcClient := types.NewAuthServiceClient(conn)
		grpcRes, err := grpcClient.ValidateToken(context.Background(), &types.ValidateTokenRequest{
			AccessToken: state.accessToken2,
		})
		if err != nil {
			fail(t, "grpc validate failed: %v", err)
		}
		if grpcRes == nil || !grpcRes.Valid {
			fail(t, "expected grpc validate to return valid=true")
		}

		grpcRes, err = grpcClient.ValidateToken(context.Background(), &types.ValidateTokenRequest{
			AccessToken: "invalid",
		})
		if err != nil {
			fail(t, "grpc validate invalid failed: %v", err)
		}
		if grpcRes.Valid {
			fail(t, "expected grpc validate invalid to return valid=false")
		}
	})
}

func TestAuthE2E_GRPCFlow(t *testing.T) {
	grpcAddr := os.Getenv("AUTH_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = defaultGRPCAddr
	}
	httpBase := os.Getenv("AUTH_HTTP_URL")
	if httpBase == "" {
		httpBase = defaultHTTPBase
	}

	if err := waitForHTTP(httpBase, 30*time.Second); err != nil {
		t.Fatalf("http not ready: %v", err)
	}
	if err := waitForGRPC(grpcAddr, 30*time.Second); err != nil {
		t.Fatalf("grpc not ready: %v", err)
	}

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc new client failed: %v", err)
	}
	defer conn.Close()

	client := types.NewAuthServiceClient(conn)
	state := struct {
		email           string
		password        string
		newPassword     string
		confirmToken    string
		userID          uint64
		accessToken     string
		refreshToken    string
		oldRefreshToken string
		resetToken      string
	}{
		email:       fmt.Sprintf("grpc+%d@example.com", time.Now().UnixNano()),
		password:    "StrongPass1!",
		newPassword: "NewStrongPass1!",
	}

	abort := false
	fail := func(t *testing.T, format string, args ...any) {
		abort = true
		t.Fatalf(format, args...)
	}
	step := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			if abort {
				t.Skip("previous step failed")
			}
			fn(t)
		})
	}

	step("RegisterWeakPassword", func(t *testing.T) {
		_, err = client.Register(context.Background(), &types.RegisterRequest{
			Email:    "weak-" + state.email,
			Password: "short",
		})
		if err == nil {
			fail(t, "expected weak password error")
		}
	})

	step("Register", func(t *testing.T) {
		regRes, err := client.Register(context.Background(), &types.RegisterRequest{
			Email:    state.email,
			Password: state.password,
		})
		if err != nil {
			fail(t, "register failed: %v", err)
		}
		if regRes.ConfirmToken == "" || regRes.UserId == 0 {
			fail(t, "expected confirm_token and user_id")
		}
		state.confirmToken = regRes.ConfirmToken
		state.userID = regRes.UserId
	})

	step("GenerateConfirmToken", func(t *testing.T) {
		genRes, err := client.GenerateConfirmToken(context.Background(), &types.GenerateConfirmTokenRequest{
			Email: state.email,
		})
		if err != nil {
			fail(t, "generate confirm token failed: %v", err)
		}
		if genRes.ConfirmToken == "" {
			fail(t, "expected confirm token from generate")
		}
	})

	step("LoginBeforeConfirm", func(t *testing.T) {
		_, err = client.Login(context.Background(), &types.LoginRequest{
			Email:    state.email,
			Password: state.password,
		})
		if err == nil {
			fail(t, "expected login before confirm to fail")
		}
	})

	step("ConfirmAccount", func(t *testing.T) {
		_, err = client.ConfirmAccount(context.Background(), &types.ConfirmAccountRequest{
			Token: state.confirmToken,
		})
		if err != nil {
			fail(t, "confirm failed: %v", err)
		}
	})

	step("GenerateConfirmTokenAfterConfirm", func(t *testing.T) {
		_, err = client.GenerateConfirmToken(context.Background(), &types.GenerateConfirmTokenRequest{
			Email: state.email,
		})
		if err == nil {
			fail(t, "expected generate confirm token to fail after confirm")
		}
	})

	step("Login", func(t *testing.T) {
		loginRes, err := client.Login(context.Background(), &types.LoginRequest{
			Email:    state.email,
			Password: state.password,
		})
		if err != nil {
			fail(t, "login failed: %v", err)
		}
		if loginRes.AccessToken == "" || loginRes.RefreshToken == "" {
			fail(t, "expected tokens")
		}
		state.accessToken = loginRes.AccessToken
		state.refreshToken = loginRes.RefreshToken
	})

	step("RefreshToken", func(t *testing.T) {
		refreshRes, err := client.RefreshToken(context.Background(), &types.RefreshTokenRequest{
			RefreshToken: state.refreshToken,
		})
		if err != nil {
			fail(t, "refresh failed: %v", err)
		}
		if refreshRes.RefreshToken == "" {
			fail(t, "expected new refresh token")
		}
		state.oldRefreshToken = state.refreshToken
		state.refreshToken = refreshRes.RefreshToken
	})

	step("OldRefreshTokenInvalid", func(t *testing.T) {
		_, err = client.RefreshToken(context.Background(), &types.RefreshTokenRequest{
			RefreshToken: state.oldRefreshToken,
		})
		if err == nil {
			fail(t, "expected old refresh token to fail")
		}
	})

	step("ChangePasswordWeak", func(t *testing.T) {
		_, err = client.ChangePassword(context.Background(), &types.ChangePasswordRequest{
			UserId:      state.userID,
			OldPassword: state.password,
			NewPassword: "short",
		})
		if err == nil {
			fail(t, "expected weak password change to fail")
		}
	})

	step("ChangePassword", func(t *testing.T) {
		_, err = client.ChangePassword(context.Background(), &types.ChangePasswordRequest{
			UserId:      state.userID,
			OldPassword: state.password,
			NewPassword: state.newPassword,
		})
		if err != nil {
			fail(t, "change password failed: %v", err)
		}
	})

	step("Logout", func(t *testing.T) {
		_, err = client.Logout(context.Background(), &types.LogoutRequest{
			RefreshToken: state.refreshToken,
			AccessToken:  state.accessToken,
		})
		if err != nil {
			fail(t, "logout failed: %v", err)
		}
	})

	step("LogoutInvalidatesRefresh", func(t *testing.T) {
		_, err = client.RefreshToken(context.Background(), &types.RefreshTokenRequest{
			RefreshToken: state.refreshToken,
		})
		if err == nil {
			fail(t, "expected refresh token invalid after logout")
		}
	})

	step("RequestResetUnknownUser", func(t *testing.T) {
		_, err = client.RequestPasswordReset(context.Background(), &types.RequestPasswordResetRequest{
			Email: "missing-" + state.email,
		})
		if err != nil {
			fail(t, "request reset for missing user should succeed: %v", err)
		}
	})

	step("RequestReset", func(t *testing.T) {
		resetRes, err := client.RequestPasswordReset(context.Background(), &types.RequestPasswordResetRequest{
			Email: state.email,
		})
		if err != nil {
			fail(t, "request reset failed: %v", err)
		}
		if resetRes.ResetToken == "" {
			fail(t, "expected reset token")
		}
		state.resetToken = resetRes.ResetToken
	})

	step("ResetWeakPassword", func(t *testing.T) {
		_, err = client.ResetPassword(context.Background(), &types.ResetPasswordRequest{
			Token:       state.resetToken,
			NewPassword: "short",
		})
		if err == nil {
			fail(t, "expected weak reset password to fail")
		}
	})

	step("ResetPassword", func(t *testing.T) {
		_, err = client.ResetPassword(context.Background(), &types.ResetPasswordRequest{
			Token:       state.resetToken,
			NewPassword: state.password,
		})
		if err != nil {
			fail(t, "reset password failed: %v", err)
		}
	})

	step("ResetPasswordUsedToken", func(t *testing.T) {
		_, err = client.ResetPassword(context.Background(), &types.ResetPasswordRequest{
			Token:       state.resetToken,
			NewPassword: state.password,
		})
		if err == nil {
			fail(t, "expected reset with used token to fail")
		}
	})
}

func (c *httpClient) postJSONWithAuth(t *testing.T, path, accessToken string, body any) (*http.Response, []byte) {
	t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioReadAll(resp)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	return resp, bodyBytes
}

func ioReadAll(resp *http.Response) ([]byte, error) {
	buf := &bytes.Buffer{}
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}
