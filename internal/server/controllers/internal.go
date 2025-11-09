package controllers

import (
	"net/http"
	"terralist/internal/server/handlers"
	"terralist/pkg/api"
	"terralist/pkg/auth"
	"terralist/pkg/rbac"

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
	AuthorizedUsers       string
	Authorization         *handlers.Authorization
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
				"host":             c.HostURL,
				"domain":           c.CanonicalDomain,
				"company":          c.CustomCompanyName,
				"authorized_users": c.AuthorizedUsers,
				"auth": gin.H{
					"providers":              c.OauthProviders,
					"endpoint":               c.AuthorizationEndpoint,
					"session_endpoint":       c.SessionDetailsRoute,
					"clear_session_endpoint": c.ClearSessionRoute,
				},
			})
		},
	)

	api.GET(
		"/permissions/settings",
		func(ctx *gin.Context) {
			user, err := handlers.GetFromContext[auth.User](ctx, "user")
			if err != nil {
				// If user is not authenticated, check if anonymous access is allowed
				user = &auth.User{
					Name: rbac.SubjectAnonymous,
				}
			}

			canAccess := c.Authorization.CanPerform(*user, rbac.ResourceSettings, rbac.ActionGet, "*")

			ctx.JSON(http.StatusOK, gin.H{
				"can_access_settings": canAccess,
			})
		},
	)
}
