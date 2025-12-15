package passport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	EnvAPIBaseURL = "PASSPORT_API_BASE_URL"
	EnvAPIToken   = "PASSPORT_API_TOKEN"
	EnvClientID   = "PASSPORT_CLIENT_ID"
	EnvSSOOnly    = "PASSPORT_SSO_ONLY"

	StateKeyPrefix           = "passport_sso_state_"
	DefaultStateTTLSeconds   = 10 * 60
	DefaultHTTPTimeout       = 15 * time.Second
	DefaultPreferredLanguage = ""
)

type Config struct {
	APIBaseURL string
	APIToken   string
	ClientID   string
	SSOOnly    bool
}

func LoadConfigFromEnv() Config {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(EnvAPIBaseURL)), "/")
	if base != "" && !strings.HasSuffix(base, "/api") {
		base += "/api"
	}

	return Config{
		APIBaseURL: base,
		APIToken:   strings.TrimSpace(os.Getenv(EnvAPIToken)),
		ClientID:   strings.TrimSpace(os.Getenv(EnvClientID)),
		SSOOnly:    parseBoolEnv(os.Getenv(EnvSSOOnly)),
	}
}

func (c Config) Configured() bool {
	return c.APIBaseURL != "" && c.APIToken != "" && c.ClientID != ""
}

type ConsentRequest struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Fields      []string `json:"fields"`
	State       string   `json:"state,omitempty"`
	RestartURI  string   `json:"restart_uri,omitempty"`
}

type consentRequestResponse struct {
	RequestID string `json:"request_id"`
	ConsentURL string `json:"consent_url"`
	ConsentUrl string `json:"consentUrl"`
}

func RequestConsent(ctx context.Context, cfg Config, req ConsentRequest) (string, error) {
	if !cfg.Configured() {
		return "", errors.New("passport sso is not configured")
	}

	req.ClientID = cfg.ClientID
	if req.RedirectURI == "" {
		return "", errors.New("redirect_uri is required")
	}
	if len(req.Fields) == 0 {
		return "", errors.New("fields is required")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal consent request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/services/consent/request", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create consent request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Token", cfg.APIToken)

	client := &http.Client{Timeout: DefaultHTTPTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("consent request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("consent request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed consentRequestResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse consent response: %w", err)
	}

	consentURL := strings.TrimSpace(parsed.ConsentURL)
	if consentURL == "" {
		consentURL = strings.TrimSpace(parsed.ConsentUrl)
	}
	if consentURL == "" {
		return "", errors.New("passport consent response missing consent_url")
	}

	return consentURL, nil
}

type TokenRequest struct {
	Code     string `json:"code"`
	ClientID string `json:"client_id"`
}

type Profile struct {
	ID                string `json:"id,omitempty"`
	LogtoID           string `json:"logto_id,omitempty"`
	Email             string `json:"email"`
	Nickname          string `json:"nickname,omitempty"`
	AvatarURL         string `json:"avatar_url,omitempty"`
	PreferredLanguage string `json:"preferred_language,omitempty"`
	Role              string `json:"role,omitempty"`
}

type tokenResponse struct {
	User *Profile `json:"user"`
}

func ExchangeConsentCode(ctx context.Context, cfg Config, code string) (*Profile, error) {
	if !cfg.Configured() {
		return nil, errors.New("passport sso is not configured")
	}
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("code is required")
	}

	body, err := json.Marshal(TokenRequest{Code: code, ClientID: cfg.ClientID})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIBaseURL+"/services/consent/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Token", cfg.APIToken)

	client := &http.Client{Timeout: DefaultHTTPTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed tokenResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if parsed.User == nil {
		return nil, errors.New("passport token response missing user")
	}
	return parsed.User, nil
}

func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func parseBoolEnv(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

