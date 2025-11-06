package auth

const (
	GITHUB = iota
	BITBUCKET
	GITLAB
	GOOGLE
	OIDC
	SAML
)

type Backend = int

// Creator creates the database.
type Creator interface {
	New(config Configurator) (Provider, error)
}
