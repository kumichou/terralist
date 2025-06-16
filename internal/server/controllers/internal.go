package controllers

import (
	"net/http"
	"terralist/pkg/api"

	"github.com/gin-gonic/gin"
)

// InternalController registers the endpoints used internally.
type InternalController interface {
	api.RestController
}

// DefaultInternalController is a concrete implementation of
// InternalController.
type DefaultInternalController struct {
	HostURL               string
	CanonicalDomain       string
	CustomCompanyName     string
	OauthProviders        []string
	AuthorizationEndpoint string
	SessionDetailsRoute   string
	ClearSessionRoute     string
	SettingsClaimName     string
	SettingsClaimValues   string
}

func (c *DefaultInternalController) Paths() []string {
	return []string{""} // bind to router's default
}

func (c *DefaultInternalController) Subscribe(apis ...*gin.RouterGroup) {
	api := apis[0]

	api.GET(
		"/runtime.json",
		func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{
				"host":                  c.HostURL,
				"domain":                c.CanonicalDomain,
				"company":               c.CustomCompanyName,
				"settings_claim_name":   c.SettingsClaimName,
				"settings_claim_values": c.SettingsClaimValues,
				"auth": gin.H{
					"providers":              c.OauthProviders,
					"endpoint":               c.AuthorizationEndpoint,
					"session_endpoint":       c.SessionDetailsRoute,
					"clear_session_endpoint": c.ClearSessionRoute,
				},
			})
		},
	)
}
