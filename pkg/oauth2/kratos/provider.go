// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	mfclients "github.com/absmach/magistrala/pkg/clients"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgoauth2 "github.com/absmach/magistrala/pkg/oauth2"
	ory "github.com/ory/client-go"
	"golang.org/x/oauth2"
)

const (
	providerName     = "kratos"
	defTimeout       = 1 * time.Minute
	userInfoEndpoint = "/userinfo?access_token="
	authEndpoint     = "/oauth2/auth"
	TokenEndpoint    = "/oauth2/token"
)

var scopes = []string{
	"email",
	"profile",
	"offline_access",
}

var _ mgoauth2.Provider = (*config)(nil)

type config struct {
	config        *oauth2.Config
	client        *ory.APIClient
	state         string
	baseURL       string
	uiRedirectURL string
	errorURL      string
}

// NewProvider returns a new Google OAuth provider.
func NewProvider(cfg mgoauth2.Config, baseURL, uiRedirectURL, errorURL, apiKey string) mgoauth2.Provider {
	conf := ory.NewConfiguration()
	conf.Servers = []ory.ServerConfiguration{{URL: baseURL}}
	conf.AddDefaultHeader("Authorization", "Bearer "+apiKey)
	client := ory.NewAPIClient(conf)

	return &config{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  baseURL + authEndpoint,
				TokenURL: baseURL + TokenEndpoint,
			},
			RedirectURL: cfg.RedirectURL,
			Scopes:      scopes,
		},
		client:        client,
		baseURL:       baseURL,
		state:         cfg.State,
		uiRedirectURL: uiRedirectURL,
		errorURL:      errorURL,
	}
}

func (cfg *config) Name() string {
	return providerName
}

func (cfg *config) State() string {
	return cfg.state
}

func (cfg *config) RedirectURL() string {
	return cfg.uiRedirectURL
}

func (cfg *config) ErrorURL() string {
	return cfg.errorURL
}

func (cfg *config) IsEnabled() bool {
	return cfg.config.ClientID != "" && cfg.config.ClientSecret != ""
}

func (cfg *config) Exchange(ctx context.Context, code string) (oauth2.Token, error) {
	token, err := cfg.config.Exchange(ctx, code)
	if err != nil {
		return oauth2.Token{}, err
	}

	return *token, nil
}

func (cfg *config) UserInfo(token string) (mfclients.Client, error) {
	resp, err := http.Get(cfg.baseURL + userInfoEndpoint + url.QueryEscape(token))
	if err != nil {
		return mfclients.Client{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return mfclients.Client{}, svcerr.ErrAuthentication
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return mfclients.Client{}, err
	}

	var user struct {
		ID    string `json:"sub"`
		Name  string `json:"preferred_username"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(data, &user); err != nil {
		return mfclients.Client{}, err
	}

	if user.ID == "" || user.Name == "" || user.Email == "" {
		return mfclients.Client{}, svcerr.ErrAuthentication
	}

	client := mfclients.Client{
		ID:   user.ID,
		Name: user.Name,
		Credentials: mfclients.Credentials{
			Identity: user.Email,
		},
		Metadata: map[string]interface{}{
			"oauth_provider": providerName,
		},
		Status: mfclients.EnabledStatus,
	}

	return client, nil
}
