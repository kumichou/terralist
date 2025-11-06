package google

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"terralist/pkg/auth"

	"github.com/rs/zerolog/log"
)

type Provider struct {
	ClientID     string
	ClientSecret string
	Domain       string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type userInfoResponse struct {
	Id       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Domain   string `json:"hd"`
	Verified bool   `json:"verified_email"`
}

type directoryGroupsResponse struct {
	Groups []struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"groups"`
}

var (
	httpClient = &http.Client{}
)

func (p *Provider) Name() string {
	return "Google"
}

func (p *Provider) GetAuthorizeUrl(state string) string {
	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/userinfo.email",
	}

	// Add Directory API scope for Google Workspace groups
	// Note: This requires admin consent and domain-wide delegation
	if p.Domain != "" {
		scopes = append(scopes, "https://www.googleapis.com/auth/admin.directory.group.readonly")
	}

	scope := url.QueryEscape(strings.Join(scopes, " "))

	return fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&state=%s&scope=%s&response_type=code&access_type=offline",
		p.ClientID,
		state,
		scope,
	)
}

func (p *Provider) GetUserDetails(code string, user *auth.User) error {
	var t tokenResponse
	if err := p.PerformAccessTokenRequest(code, &t); err != nil {
		return err
	}

	name, email, domain, err := p.PerformUserInfoRequest(t)
	if err != nil {
		return err
	}

	// Validate domain if specified (Google Workspace)
	if p.Domain != "" && domain != p.Domain {
		return fmt.Errorf("user domain %s does not match required domain %s", domain, p.Domain)
	}

	// Retrieve Google Workspace groups if domain is specified
	var groups []string
	if p.Domain != "" {
		userGroups, err := p.PerformGroupsRequest(t, email)
		if err != nil {
			// Log the error but don't fail - groups are optional
			log.Warn().Err(err).Msg("Failed to retrieve Google Workspace groups, continuing without groups")
		} else {
			groups = userGroups
		}
	}

	user.Name = name
	user.Email = email
	user.Groups = groups

	return nil
}

func (p *Provider) PerformAccessTokenRequest(code string, t *tokenResponse) error {
	tokenURL := "https://oauth2.googleapis.com/token"

	data := url.Values{}
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", "urn:ietf:wg:oauth:2.0:oob") // For desktop apps, but should work

	req, err := http.NewRequest(http.MethodPost, tokenURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.URL.RawQuery = data.Encode()

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("Google OAuth responded with status %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(t); err != nil {
		return err
	}

	return nil
}

func (p *Provider) PerformUserInfoRequest(t tokenResponse) (string, string, string, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"

	req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		return "", "", "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))

	res, err := httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", "", "", fmt.Errorf("Google userinfo responded with status %d", res.StatusCode)
	}

	var userInfo userInfoResponse
	if err := json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		return "", "", "", err
	}

	if !userInfo.Verified {
		return "", "", "", fmt.Errorf("email address is not verified")
	}

	return userInfo.Name, userInfo.Email, userInfo.Domain, nil
}

func (p *Provider) PerformGroupsRequest(t tokenResponse, userEmail string) ([]string, error) {
	groupsURL := fmt.Sprintf("https://www.googleapis.com/admin/directory/v1/groups?userKey=%s", url.QueryEscape(userEmail))

	req, err := http.NewRequest(http.MethodGet, groupsURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Google Directory API responded with status %d", res.StatusCode)
	}

	var groupsResp directoryGroupsResponse
	if err := json.NewDecoder(res.Body).Decode(&groupsResp); err != nil {
		return nil, err
	}

	// Extract group emails as group identifiers
	var groups []string
	for _, group := range groupsResp.Groups {
		groups = append(groups, group.Email)
	}

	return groups, nil
}
