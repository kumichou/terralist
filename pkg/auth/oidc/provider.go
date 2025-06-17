package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"terralist/pkg/auth"

	"github.com/rs/zerolog/log"
)

// Provider is the concrete implementation of oauth.Engine.
type Provider struct {
	ClientID     string
	ClientSecret string
	AuthorizeUrl string
	TokenUrl     string
	UserInfoUrl  string
	Scope        string
	RedirectUrl  string
	ClaimName    string
	ClaimValues  string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

var (
	httpClient = &http.Client{}
)

func (p *Provider) Name() string {
	return "OIDC"
}

func (p *Provider) GetAuthorizeUrl(state string) string {
	queryParams := url.Values{
		"client_id":     []string{p.ClientID},
		"state":         []string{state},
		"response_type": []string{"code"},
		"redirect_uri":  []string{p.RedirectUrl},
		"scope":         []string{p.Scope},
	}
	return fmt.Sprintf(
		"%s?%s",
		p.AuthorizeUrl,
		queryParams.Encode(),
	)
}

func (p *Provider) GetUserDetails(code string, user *auth.User) error {
	var t tokenResponse
	if err := p.PerformAccessTokenRequest(code, &t); err != nil {
		return err
	}

	name, email, claims, err := p.PerformUserInfoRequest(t)
	if err != nil {
		return err
	}

	user.Name = name
	user.Email = email
	user.Claims = claims

	return nil
}

func (p *Provider) PerformAccessTokenRequest(code string, t *tokenResponse) error {
	reqBody := url.Values{
		"client_id":     []string{p.ClientID},
		"client_secret": []string{p.ClientSecret},
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{p.RedirectUrl},
	}
	req, err := http.NewRequest(http.MethodPost, p.TokenUrl, strings.NewReader(reqBody.Encode()))

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("oidc token request responded with status %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(t); err != nil {
		return err
	}

	return nil
}

func (p *Provider) PerformUserInfoRequest(t tokenResponse) (string, string, map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, p.UserInfoUrl, nil)
	if err != nil {
		return "", "", nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))

	res, err := httpClient.Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", "", nil, fmt.Errorf("oidc user info request responded with status %d", res.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return "", "", nil, err
	}

	// This is a temporary block to print the claims for debugging.
	log.Info().
		Interface("claims", data).
		Msg("Received OIDC UserInfo response")

	if p.ClaimName != "" && p.ClaimValues != "" {
		allowedValues := strings.Split(p.ClaimValues, ",")
		if claims, ok := data[p.ClaimName].([]interface{}); ok {
			userClaims := make(map[string]bool)
			for _, claim := range claims {
				if claimStr, ok := claim.(string); ok {
					userClaims[claimStr] = true
				}
			}
			for _, allowedValue := range allowedValues {
				if _, ok := userClaims[allowedValue]; ok {
					goto validationSuccess
				}
			}
		} else if claim, ok := data[p.ClaimName].(string); ok {
			for _, allowedValue := range allowedValues {
				if claim == allowedValue {
					goto validationSuccess
				}
			}
		}
		return "", "", nil, fmt.Errorf("user does not have the required claim")
	}

validationSuccess:

	var sub string
	var email string
	var ok bool

	if sub, ok = data["sub"].(string); !ok {
		return "", "", nil, fmt.Errorf("no user provided")
	}

	if email, ok = data["email"].(string); !ok {
		return "", "", nil, fmt.Errorf("no email provided")
	}

	return sub, email, data, nil
}
